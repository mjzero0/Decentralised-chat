import json
import uuid
import time
import base64
from typing import Any, Dict
import hashlib

# ---------- In-memory tables ----------
servers = {}         # server_id -> link (all other servers)
server_addrs = {}    # server_id -> (host, port) (all other servers)
local_users = {}     # user_id -> link (users belong to this server)
user_locations = {}  # user_id -> "local" | server_id (all users)
# Each Server MUST keep a short-term seen_ids cache for server-delivered frames (by (ts,from,to,hash(payload))) 
# and drop duplicates.
seen_ids = set()     # {(ts, from, to, sha256(payload))}

# helper: check if string is valid UUID
def is_valid_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except Exception:
        return False

# secure envelope generator
def make_envelope(msg_type: str, sender: str, receiver: str, payload: Dict[str, Any], sig: str = "") -> Dict[str, Any]:
    # validations
    if not isinstance(msg_type, str) or not msg_type:
        raise ValueError("Type must be a non-empty string")

    if not (is_valid_uuid(sender)):
        raise ValueError(f"Invalid sender ID: {sender}")

    if receiver != "*" and not is_valid_uuid(receiver):
        raise ValueError(f"Invalid receiver ID: {receiver}")

    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object (dict)")

    # sig must be base64url (if provided)
    if sig and not all(c.isalnum() or c in "-_" for c in sig):
        raise ValueError("sig must be base64url-encoded")

    # --- envelope construction ---
    envelope = {
        "type": msg_type,                  # case-sensitive
        "from": sender,                    # UUID
        "to": receiver,                    # UUID or "*"
        "ts": int(time.time() * 1000),     # Unix timestamp in ms
        "payload": payload,                # JSON object
        "sig": sig                         # base64url signature (empty for now)
    }
    return envelope

def canonical_payload(payload: Dict[str, Any]) -> str:
    """Return canonical JSON string (sorted keys, no whitespace)."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)

# this function is for turning the above dictionary format into a json file
# json.dumps does that
def to_json(envelope: Dict[str, Any]) -> str:
    return json.dumps(envelope) + "\n"

# just use a fake sign and fake verify (will change it when the voting ends)
def fake_sign(payload: Dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_payload(payload).encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

def fake_verify(payload: Dict[str, Any], sig: str) -> bool:
    expected = fake_sign(payload)
    return expected == sig

def make_signed_envelope(msg_type, sender, receiver, payload):
    env = make_envelope(msg_type, sender, receiver, payload)
    env["sig"] = fake_sign(payload)   # use fake sign for now
    return env

# not sure - the file does not specifiy which type can omit sig
def verify_transport_sig(env: Dict[str, Any]) -> bool:
    # HELLO/BOOTSTRAP MAY omit sig
    if env["type"] in ("USER_HELLO", "SERVER_HELLO_JOIN") and not env.get("sig"):
        return True
    if "sig" not in env or "payload" not in env:
        return False
    return fake_verify(env["payload"], env["sig"])

def frame_fingerprint(env: Dict[str, Any]) -> str:
    h = hashlib.sha256(canonical_payload(env["payload"]).encode()).digest()
    return f'{env["ts"]}|{env["from"]}|{env["to"]}|{base64.urlsafe_b64encode(h).decode().rstrip("=")}'

# check if it's duplicate, if is, then drop
def drop_if_seen(env: Dict[str, Any]) -> bool:
    fp = frame_fingerprint(env)
    if fp in seen_ids:
        return True
    seen_ids.add(fp)
    return False

# --- Example usage ---
if __name__ == "__main__":
    sender_id = str(uuid.uuid4())
    receiver_id = str(uuid.uuid4())
    payload = {"msg": "hello"}
    env = make_signed_envelope("MSG_DIRECT", sender_id, receiver_id, payload)
    print(to_json(env))
    print(fake_verify(payload, env["sig"]))