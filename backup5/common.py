import json
import uuid
import time
import base64
from typing import Any, Dict
import hashlib

import os, hashlib, base64

# NEW: cryptography primitives for RSA-4096, OAEP(SHA-256), RSASSA-PSS(SHA-256)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# === Your server's key material (example placeholders) =======================
# In real code, load from your persistent keystore / DB.
SERVER_PRIVATE_KEY_PEM = None  # set to your PEM bytes
SERVER_PUBLIC_KEY_B64U = None  # base64url(no padding) of DER SubjectPublicKeyInfo

# helper: base64url (no padding) ---------------------------------------------
def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64u_decode(s: str) -> bytes:
    # add padding back if needed
    pad = '=' * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)

# helper: check if string is valid UUID
def is_valid_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except Exception:
        return False

# canonical JSON helpers (payload only per §12 transport signature)
def canonical_payload(payload: Dict[str, Any]) -> bytes:
    """Return canonical JSON bytes for payload (sorted keys, no whitespace)."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

# === RSA-4096 helpers (generate/load/serialize) ==============================
# NEW: generate a 4096-bit RSA key (for tests / dev)
def generate_rsa4096():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

# NEW: load private key from PEM (PKCS#8 or traditional), no password here for simplicity
def load_private_key_pem(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())

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

# === RSA-OAEP (SHA-256) encryption / decryption ==============================
# Spec §4: All payloads MUST be encrypted directly with RSA-OAEP (SHA-256). :contentReference[oaicite:1]{index=1}
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

# === RSASSA-PSS (SHA-256) signatures ========================================
# Spec §4: All payloads MUST be signed with RSASSA-PSS (SHA-256). :contentReference[oaicite:2]{index=2}
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

# secure envelope generator
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

    # # sig must be base64url (if provided)
    # if sig and not all(c.isalnum() or c in "-_" for c in sig):
    #     raise ValueError("sig must be base64url-encoded")

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

# this function is for turning the above dictionary format into a json file
# json.dumps does that
def to_json(envelope: Dict[str, Any]) -> str:
    return json.dumps(envelope) + "\n"

# NEW: transport signing over canonical payload (§12: transport sig covers payload only) :contentReference[oaicite:5]{index=5}
def sign_transport_payload(privkey, payload_obj: Dict[str, Any]) -> str:
    sig = rsassa_pss_sign(privkey, canonical_payload(payload_obj))
    return b64u_encode(sig)

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

# # check if it's duplicate, if is, then drop
# def drop_if_seen(env: Dict[str, Any]) -> bool:
#     fp = frame_fingerprint(env)
#     if fp in seen_ids:
#         return True
#     seen_ids.add(fp)
#     return False

# === Example usage: DM build path (client-side style) ========================
if __name__ == "__main__":
    # For demo: generate ephemeral keys (replace with real stored keys)
    sender_priv = generate_rsa4096()
    sender_pub_b64u = public_key_b64u_from_private(sender_priv)
    recipient_priv = generate_rsa4096()
    recipient_pub_b64u = public_key_b64u_from_private(recipient_priv)

    # IDs
    sender_id = str(uuid.uuid4())
    receiver_id = str(uuid.uuid4())

    # 1) Encrypt the plaintext with recipient RSA-4096 using OAEP(SHA-256) (§4)
    plaintext = json.dumps({"msg": "hello"}).encode("utf-8")
    recip_pub = load_public_key_b64u(recipient_pub_b64u)
    ciphertext = rsa_oaep_encrypt(recip_pub, plaintext)
    ciphertext_b64u = b64u_encode(ciphertext)

    # 2) Prepare content_sig over SHA256(ciphertext||from||to||ts), signed by sender (PSS) (§12)
    ts = int(time.time() * 1000)
    content_sig_b64u = make_dm_content_sig(sender_priv, ciphertext_b64u, sender_id, receiver_id, ts)

    # 3) Build the DM payload as per §9.2 (server MUST NOT decrypt) and sign transport over payload (§12) :contentReference[oaicite:9]{index=9}
    dm_payload = {
        "ciphertext": ciphertext_b64u,
        "sender_pub": sender_pub_b64u,
        "content_sig": content_sig_b64u
    }

    # For transport signature, use the *server* private key when sending server→server or server→user.
    # Here we simulate using sender's key; in your server, replace with SERVER_PRIVATE_KEY_PEM.
    transport_priv = sender_priv  # replace with load_private_key_pem(SERVER_PRIVATE_KEY_PEM)
    env = make_signed_envelope("MSG_DIRECT", sender_id, receiver_id, dm_payload, transport_priv)

    # Show frame
    print(to_json(env))

    # 4) Receiver verifies content_sig and decrypts:
    ok = verify_dm_content_sig(
        sender_pub_b64u=env["payload"]["sender_pub"],
        ciphertext_b64u=env["payload"]["ciphertext"],
        sender_id=env["from"],
        recipient_id=env["to"],
        ts=env["ts"],
        content_sig_b64u=env["payload"]["content_sig"]
    )
    print("content_sig valid?", ok)
    decrypted = rsa_oaep_decrypt(recipient_priv, b64u_decode(env["payload"]["ciphertext"]))
    print("plaintext:", decrypted.decode("utf-8"))



  
# password hashing
def hash_password(password: str, salt: bytes = None) -> str:
    if not salt:
        salt = os.urandom(16)  # 16-byte random salt
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt + key).decode()

def verify_password(stored: str, password: str) -> bool:
    raw = base64.b64decode(stored.encode())
    salt, key = raw[:16], raw[16:]
    new_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return new_key == key
