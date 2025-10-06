import json
import uuid
import time
import base64
from typing import Any, Dict
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature



def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64u_decode(s: str) -> bytes:
    pad = '=' * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)

# helper: check if string is valid UUID
def is_valid_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except Exception:
        return False

def canonical_payload(payload: Dict[str, Any]) -> bytes:
    """Return canonical JSON bytes for payload (sorted keys, no whitespace)."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

# NEW: generate a 4096-bit RSA key (for tests / dev)
def generate_rsa4096():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())


# NEW: export public key (DER, SubjectPublicKeyInfo), then base64url
def public_key_b64u_from_private(priv) -> str:
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64u_encode(pub_der)

# NEW: load public key from base64url DER
def load_public_key_b64u(b64u_der: str):
    der = b64u_decode(b64u_der)
    return serialization.load_der_public_key(der, backend=default_backend())


# All payloads MUST be encrypted directly with RSA-OAEP (SHA-256). 
def rsa_oaep_encrypt(pubkey, plaintext: bytes) -> bytes:
    return pubkey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_oaep_decrypt(privkey, ciphertext: bytes) -> bytes:
    return privkey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# === RSASSA-PSS (SHA-256) signatures 
def rsassa_pss_sign(privkey, data: bytes) -> bytes:
    return privkey.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsassa_pss_verify(pubkey, data: bytes, signature: bytes) -> bool:
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


def sign_transport_payload(privkey, payload_obj: Dict[str, Any]) -> str:
    sig = rsassa_pss_sign(privkey, canonical_payload(payload_obj))
    return b64u_encode(sig)

def make_envelope(msg_type: str, sender: str, receiver: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    # validations
    if not isinstance(msg_type, str) or not msg_type:
        raise ValueError("Type must be a non-empty string")

    if not (is_valid_uuid(sender)):
        raise ValueError(f"Invalid sender ID: {sender}")

    if receiver != "*" and not is_valid_uuid(receiver):
        raise ValueError(f"Invalid receiver ID: {receiver}")

    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object (dict)")


    # --- envelope construction ---
    envelope = {
        "type": msg_type,                  # case-sensitive
        "from": sender,                    # UUID
        "to": receiver,                    # UUID or "*"
        "ts": int(time.time() * 1000),     # Unix timestamp in ms
        "payload": payload,                # JSON object
        # "sig": sig                         # base64url signature (empty for now)
    }
    return envelope



def verify_transport_sig(env: Dict[str, Any], from_pubkey_b64u: str) -> bool:
    # HELLO/BOOTSTRAP MAY omit sig; otherwise REQUIRED (§7, §12) :contentReference[oaicite:6]{index=6}
    if env["type"] in ("USER_HELLO", "SERVER_HELLO_JOIN") and not env.get("sig"):
        return True
    if "sig" not in env or "payload" not in env:
        return False
    pub = load_public_key_b64u(from_pubkey_b64u)
    sig = b64u_decode(env["sig"])
    return rsassa_pss_verify(pub, canonical_payload(env["payload"]), sig)

# NEW: content signature for DM: SHA256(ciphertext || from || to || ts) then PSS (§12) :contentReference[oaicite:7]{index=7}
def make_dm_content_sig(sender_privkey, ciphertext_b64u: str, sender_id: str, recipient_id: str, ts: int) -> str:
    digest = hashlib.sha256()
    digest.update(b64u_decode(ciphertext_b64u))
    digest.update(sender_id.encode())
    digest.update(recipient_id.encode())
    digest.update(str(ts).encode())
    h = digest.digest()
    sig = rsassa_pss_sign(sender_privkey, h)
    return b64u_encode(sig)

def verify_dm_content_sig(sender_pub_b64u: str, ciphertext_b64u: str, sender_id: str, recipient_id: str, ts: int, content_sig_b64u: str) -> bool:
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

# NEW: build a signed envelope (transport sig) with supplied private key
def make_signed_envelope(msg_type: str, sender: str, receiver: str, payload: Dict[str, Any], transport_privkey):
    env = make_envelope(msg_type, sender, receiver, payload)
    env["sig"] = sign_transport_payload(transport_privkey, env["payload"])
    return env

# CHANGED: fingerprint still uses canonical payload hash (spec §10 duplicate suppression) :contentReference[oaicite:8]{index=8}
def frame_fingerprint(env: Dict[str, Any]) -> str:
    h = hashlib.sha256(canonical_payload(env["payload"])).digest()
    return f'{env["ts"]}|{env["from"]}|{env["to"]}|{b64u_encode(h)}'

