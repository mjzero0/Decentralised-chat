"""
SOCP Cryptography Primitives - RSA-4096, OAEP, RSASSA-PSS, Content Signatures

Implements required cryptographic utilities for the Secure Overlay Chat Protocol v1.3,
including:
- RSA key generation, serialization, and base64url conversion
- RSA-OAEP encryption/decryption
- RSASSA-PSS digital signatures
- Canonical JSON encoding
- Transport and content signing as per SOCP §12
"""

import json
import uuid
import time
import base64
from typing import Any, Dict
import hashlib

import os, hashlib, base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


SERVER_PRIVATE_KEY_PEM = None
SERVER_PUBLIC_KEY_B64U = None

def b64u_encode(b: bytes) -> str:
    """Encode bytes to base64url format without padding."""
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64u_decode(s: str) -> bytes:
    """Decode a base64url-encoded string to bytes, adding padding if necessary."""
    pad = '=' * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)

def is_valid_uuid(val: str) -> bool:
    """Return True if the given string is a valid UUID."""
    try:
        uuid.UUID(val)
        return True
    except Exception:
        return False

def canonical_payload(payload: Dict[str, Any]) -> bytes:
    """Return canonical JSON bytes for payload (sorted keys, no whitespace)."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

def generate_rsa4096():
    """Generate a new 4096-bit RSA key pair."""
    return rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

def load_private_key_pem(pem_bytes: bytes):
    """Load an RSA private key from PEM bytes."""
    return serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())

def public_key_b64u_from_private(priv) -> str:
    """Return base64url-encoded DER SubjectPublicKeyInfo from an RSA private key."""
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64u_encode(pub_der)

def load_public_key_b64u(b64u_der: str):
    """Load an RSA public key from a base64url-encoded DER string."""
    der = b64u_decode(b64u_der)
    return serialization.load_der_public_key(der, backend=default_backend())

def rsa_oaep_encrypt(pubkey, plaintext: bytes) -> bytes:
    """Encrypt plaintext with RSA-OAEP (SHA-256) using recipient's public key."""
    return pubkey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_oaep_decrypt(privkey, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext with RSA-OAEP (SHA-256) using recipient's private key."""
    return privkey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsassa_pss_sign(privkey, data: bytes) -> bytes:
    """Sign the given data using RSASSA-PSS (SHA-256)."""
    return privkey.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsassa_pss_verify(pubkey, data: bytes, signature: bytes) -> bool:
    """Verify RSASSA-PSS signature (SHA-256) on given data using public key."""
    try:
        pubkey.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def make_envelope(msg_type: str, sender: str, receiver: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construct a protocol envelope with metadata and payload, without signature.

    Args:
        msg_type: Type of the message (e.g., MSG_DIRECT)
        sender: UUID of sender
        receiver: UUID of receiver or '*'
        payload: Payload object (dict)

    Returns:
        Envelope dictionary conforming to SOCP §7
    """
    if not isinstance(msg_type, str) or not msg_type:
        raise ValueError("Type must be a non-empty string")

    if not (is_valid_uuid(sender)):
        raise ValueError(f"Invalid sender ID: {sender}")

    if receiver != "*" and not is_valid_uuid(receiver):
        raise ValueError(f"Invalid receiver ID: {receiver}")

    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object (dict)")

    envelope = {
        "type": msg_type,
        "from": sender,
        "to": receiver,
        "ts": int(time.time() * 1000),
        "payload": payload,
    }
    return envelope

def to_json(envelope: Dict[str, Any]) -> str:
    """Serialize a protocol envelope dictionary into JSON string with newline."""
    return json.dumps(envelope) + "\n"

def sign_transport_payload(privkey, payload_obj: Dict[str, Any]) -> str:
    """
    Create transport signature over canonicalized payload using RSASSA-PSS.

    Args:
        privkey: RSA private key object
        payload_obj: JSON payload dict

    Returns:
        base64url-encoded signature string
    """
    sig = rsassa_pss_sign(privkey, canonical_payload(payload_obj))
    return b64u_encode(sig)

def verify_transport_sig(env: Dict[str, Any], from_pubkey_b64u: str) -> bool:
    """
    Verify the transport signature on a message envelope.

    Args:
        env: Full envelope including payload and sig fields
        from_pubkey_b64u: Sender's base64url public key

    Returns:
        True if signature is valid, False otherwise
    """
    if env["type"] in ("USER_HELLO", "SERVER_HELLO_JOIN") and not env.get("sig"):
        return True
    if "sig" not in env or "payload" not in env:
        return False
    pub = load_public_key_b64u(from_pubkey_b64u)
    sig = b64u_decode(env["sig"])
    return rsassa_pss_verify(pub, canonical_payload(env["payload"]), sig)

def make_dm_content_sig(sender_privkey, ciphertext_b64u: str, sender_id: str, recipient_id: str, ts: int) -> str:
    """
    Create content signature for a direct message (DM) frame.

    Args:
        sender_privkey: RSA private key of sender
        ciphertext_b64u: Base64url-encoded ciphertext
        sender_id: UUID of sender
        recipient_id: UUID of recipient
        ts: Timestamp in milliseconds

    Returns:
        base64url-encoded RSASSA-PSS signature
    """
    digest = hashlib.sha256()
    digest.update(b64u_decode(ciphertext_b64u))
    digest.update(sender_id.encode())
    digest.update(recipient_id.encode())
    digest.update(str(ts).encode())
    h = digest.digest()
    sig = rsassa_pss_sign(sender_privkey, h)
    return b64u_encode(sig)

def verify_dm_content_sig(sender_pub_b64u: str, ciphertext_b64u: str, sender_id: str, recipient_id: str, ts: int, content_sig_b64u: str) -> bool:
    """
    Verify DM content signature over SHA-256(ciphertext || from || to || ts)

    Args:
        sender_pub_b64u: Base64url public key of sender
        ciphertext_b64u: Base64url-encoded ciphertext
        sender_id: UUID of sender
        recipient_id: UUID of recipient
        ts: Timestamp
        content_sig_b64u: base64url content signature

    Returns:
        True if valid, False if invalid or tampered
    """
    pub = load_public_key_b64u(sender_pub_b64u)
    digest = hashlib.sha256()
    digest.update(b64u_decode(ciphertext_b64u))
    digest.update(sender_id.encode())
    digest.update(recipient_id.encode())
    digest.update(str(ts).encode())
    h = digest.digest()
    try:
        pub.verify(
            b64u_decode(content_sig_b64u),
            h,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def make_signed_envelope(msg_type: str, sender: str, receiver: str, payload: Dict[str, Any], transport_privkey):
    """
    Construct a signed envelope with a transport signature over the payload.

    Args:
        msg_type: Message type
        sender: Sender UUID
        receiver: Receiver UUID or '*'
        payload: JSON payload object
        transport_privkey: Private key used to sign the payload

    Returns:
        Envelope dictionary including signature
    """
    env = make_envelope(msg_type, sender, receiver, payload)
    env["sig"] = sign_transport_payload(transport_privkey, env["payload"])
    return env

def frame_fingerprint(env: Dict[str, Any]) -> str:
    """
    Generate a fingerprint for a frame for duplicate detection.

    Format: "<ts>|<from>|<to>|<SHA256(payload)>"

    Args:
        env: Message envelope

    Returns:
        String fingerprint of the message
    """
    h = hashlib.sha256(canonical_payload(env["payload"])).digest()
    return f'{env["ts"]}|{env["from"]}|{env["to"]}|{b64u_encode(h)}'

def hash_password(password: str, salt: bytes = None) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with optional salt.

    Args:
        password: User password
        salt: Optional 16-byte salt

    Returns:
        base64-encoded (salt + key) string
    """
    if not salt:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt + key).decode()

def verify_password(stored: str, password: str) -> bool:
    """
    Verify a password against a stored salted hash.

    Args:
        stored: base64-encoded (salt + key) string
        password: password to check

    Returns:
        True if password matches, else False
    """
    raw = base64.b64decode(stored.encode())
    salt, key = raw[:16], raw[16:]
    new_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return new_key == key
