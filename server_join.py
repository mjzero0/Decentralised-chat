import asyncio
import websockets
import uuid
import time
import json
import base64
import common

# -------------------------
# CONFIGURATION
# -------------------------

INTRODUCER_HOST = "127.0.0.1"
INTRODUCER_PORT = 8765
INTRODUCER_ADDR = f"{INTRODUCER_HOST}:{INTRODUCER_PORT}"

# -------------------------
# FAKE RSA PUBLIC KEY (normally base64url of DER bytes)
# -------------------------
FAKE_PUBKEY = base64.urlsafe_b64encode(b"my_fake_rsa_pubkey_4096_bytes").decode().rstrip("=")

# -------------------------
# ENVELOPE CREATOR
# -------------------------

def handle_server_hello_join(server_id: str, host: str, port: int) -> dict:
    return {
        "type": "SERVER_HELLO_JOIN",
        "from": server_id,
        "to": f"{host}:{port}",
        "ts": int(time.time() * 1000),
        "payload": {
            "host": host,
            "port": port,
            "pubkey": FAKE_PUBKEY
        },
        "sig": ""  # allowed to omit in SOCP v1.2
    }

def to_json(envelope: dict) -> str:
    return json.dumps(envelope) + "\n"

def handle_server_welcome(envelope: dict):
    payload = envelope["payload"]
    assigned_id = payload["assigned_id"]

    # Step 1: set server_id
    global server_id
    server_id = assigned_id
    print(f"✅ Assigned server_id: {server_id}")

    # Step 2: add introducer's pubkey/addr
    introducer_id = envelope["from"]
    common.server_addrs[introducer_id] = (INTRODUCER_HOST, INTRODUCER_PORT)
    print(f"📡 Introducer is {introducer_id}")

    # Step 3: update user_locations table（from introducer' clients）
    for client in payload.get("clients", []):
        user_id = client["user_id"]
        common.user_locations[user_id] = introducer_id
        print(f"📥 Learned user {user_id} is on server {introducer_id}")
        

    # Step 4: Optional ???
    # servers[introducer_id] = link


# -------------------------
# CLIENT LOGIC
# -------------------------

async def join_network():
    server_id = str(uuid.uuid4())
    envelope = handle_server_hello_join(server_id, INTRODUCER_HOST, INTRODUCER_PORT)

    uri = f"ws://{INTRODUCER_HOST}:{INTRODUCER_PORT}"
    async with websockets.connect(uri) as websocket:
        print("🛰️ Connected to introducer")
        await websocket.send(to_json(envelope))
        print("📤 Sent SERVER_HELLO_JOIN")

        # Wait for response (SERVER_WELCOME)
        response = await websocket.recv()
        print("📥 Received:", response)
        
        handle_server_welcome(json.loads(response))

# -------------------------
# RUN
# -------------------------

if __name__ == "__main__":
    asyncio.run(join_network())
