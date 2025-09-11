import asyncio
import websockets
import json
import time
import base64
import uuid

# Dummy RSA pubkey
FAKE_PUBKEY = base64.urlsafe_b64encode(b"fake-rsa-pubkey").decode().rstrip("=")

def now_ms():
    return int(time.time() * 1000)

def to_json(obj: dict) -> str:
    return json.dumps(obj) + "\n"

async def handle_join(websocket):
    try:
        msg = await websocket.recv()
        env = json.loads(msg)

        if env["type"] != "SERVER_HELLO_JOIN":
            await websocket.send(to_json({
                "type": "ERROR",
                "from": "introducer",
                "to": env.get("from", ""),
                "ts": now_ms(),
                "payload": {"code": "BAD_TYPE", "detail": "Expected SERVER_HELLO_JOIN"},
                "sig": ""
            }))
            return

        server_id = env["from"]
        print(f"✅ Received SERVER_HELLO_JOIN from {server_id}")

        # Build dummy SERVER_WELCOME
        welcome = {
            "type": "SERVER_WELCOME",
            "from": "introducer-0000-0000",
            "to": server_id,
            "ts": now_ms(),
            "payload": {
                "assigned_id": server_id,  # reuse the same for simplicity
                "clients": [
                    {"user_id": str(uuid.uuid4()), "host": "1.2.3.4", "port": 1234, "pubkey": FAKE_PUBKEY},
                    {"user_id": str(uuid.uuid4()), "host": "5.6.7.8", "port": 5678, "pubkey": FAKE_PUBKEY}
                ]
            },
            "sig": ""  # introducer can omit sig per your test setup
        }

        await websocket.send(to_json(welcome))
        print(f"📤 Sent SERVER_WELCOME to {server_id}")

    except Exception as e:
        print("❌ Error:", e)

async def start_server():
    print("🌐 Fake Introducer running on ws://localhost:8765")
    async with websockets.serve(handle_join, "0.0.0.0", 8765):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(start_server())
