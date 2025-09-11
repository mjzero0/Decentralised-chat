import json
import uuid
import time
import base64
from typing import Any, Dict

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

# --- Example usage ---
if __name__ == "__main__":
    sender_id = str(uuid.uuid4())
    receiver_id = str(uuid.uuid4())
    payload = {"msg": "hello"}
    env = make_envelope("MSG_DIRECT", sender_id, receiver_id, payload)
    print(to_json(env))