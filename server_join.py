import asyncio
import websockets
import uuid
import time
import json
import base64
import common
import os

# -------------------------
# CONFIGURATION
# -------------------------

INTRODUCER_HOST = "127.0.0.1"
INTRODUCER_PORT = 8765
INTRODUCER_ADDR = f"{INTRODUCER_HOST}:{INTRODUCER_PORT}"

# Your own externally accessible address and WS port (modify as needed or overwrite with environment variables)
MY_HOST = os.getenv("MY_HOST", "127.0.0.1")
MY_PORT = int(os.getenv("MY_PORT", "9001"))

# -------------------------
# FAKE RSA PUBLIC KEY (normally base64url of DER bytes)
# -------------------------
FAKE_PUBKEY = base64.urlsafe_b64encode(b"my_fake_rsa_pubkey_4096_bytes").decode().rstrip("=")

# -------------------------
# ENVELOPE CREATOR
# -------------------------

def make_server_hello_join(server_id: str, host: str, port: int) -> dict:
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
    print(f"📡 Introducer is {introducer_id}")

    # Step 3: update user_locations table（from introducer' clients）
    for client in payload.get("clients", []):
        user_id = client["user_id"]
        # TODO: CHECK IF THIS IS CORRECT
        common.user_locations[user_id] = (client["host"], client["port"])
        print(f"📥 Learned user {user_id} is on {(client["host"], client["port"])}")
        
def make_server_announce(from_id: str, host: str, port: int, pubkey_b64u: str) -> dict:
    return {
        "type": "SERVER_ANNOUNCE",
        "from": from_id,
        "to": "*", 
        "ts": int(time.time() * 1000),
        "payload": {
            "host": host,    
            "port": port,   
            "pubkey": pubkey_b64u 
        },
        "sig": "" # TODO
    }
        
def handle_server_announce(envelope: dict):
    """Receive online broadcasts from other servers and register their addresses/public keys"""
    from_id = envelope.get("from")
    payload = envelope.get("payload", {})
    host = payload.get("host")
    port = payload.get("port")
    pubkey = payload.get("pubkey")

    if server_id and from_id == server_id:
        return

    # Basic verification (signature verification can be added if necessary)
    if not (from_id and host and port):
        print(f"⚠️ Malformed SERVER_ANNOUNCE: {envelope}")
        return

    common.server_addrs[from_id] = (host, int(port), pubkey)

    print(f"🆕 Registered server {from_id} @ {host}:{port}")

async def join_network():
    temp_id = str(uuid.uuid4())
    hello = make_server_hello_join(temp_id, INTRODUCER_HOST, INTRODUCER_PORT)

    uri = f"ws://{INTRODUCER_HOST}:{INTRODUCER_PORT}"
    async with websockets.connect(uri) as websocket:
        print("🛰️ Connected to introducer")
        await websocket.send(to_json(hello))
        print("📤 Sent SERVER_HELLO_JOIN")

        # Continue reading messages: WELCOME → Send SERVER_ANNOUNCE; receive others' ANNOUNCE at the same time
        while True:
            raw = await websocket.recv()
            msg = json.loads(raw)
            mtype = msg.get("type")

            if mtype == "SERVER_WELCOME":
                handle_server_welcome(msg)

                # WELCOME and then immediately broadcast our online information (icon function)
                if server_id:
                    announce = make_server_announce(server_id, MY_HOST, MY_PORT, FAKE_PUBKEY)
                    await websocket.send(to_json(announce))
                    print(f"📣 Sent SERVER_ANNOUNCE for {server_id} ({MY_HOST}:{MY_PORT})")

            elif mtype == "SERVER_ANNOUNCE":
                handle_server_announce(msg)

            else:
                # Other types of on-demand expansion (PING, ROUTE_UPDATE, etc.)
                print(f"ℹ️ Unhandled message type: {mtype}")

# -------------------------
# RUN
# -------------------------
if __name__ == "__main__":
    asyncio.run((join_network()))