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

connected_servers = {}  # server_id -> websocket

async def handle_join(websocket):
    server_id = None
    try:
        async for msg in websocket:
            env = json.loads(msg)
            mtype = env["type"]

            if mtype == "SERVER_HELLO_JOIN":
                server_id = env["from"]
                connected_servers[server_id] = websocket

                # 发送 WELCOME
                welcome = {
                    "type": "SERVER_WELCOME",
                    "from": "introducer-0000-0000",
                    "to": server_id,
                    "ts": now_ms(),
                    "payload": {
                        "assigned_id": server_id,
                        "clients": [
                            {"user_id": str(uuid.uuid4()), "host": "1.2.3.4", "port": 1234, "pubkey": FAKE_PUBKEY},
                            {"user_id": str(uuid.uuid4()), "host": "5.6.7.8", "port": 5678, "pubkey": FAKE_PUBKEY}
                        ]
                    },
                    "sig": ""
                }
                await websocket.send(to_json(welcome))
                print(f"📤 Sent SERVER_WELCOME to {server_id}")

            elif mtype == "SERVER_ANNOUNCE":
                print(f"📡 Received SERVER_ANNOUNCE from {env['from']}")

                for other_id, other_ws in connected_servers.items():
                    if other_id != env["from"]:
                        try:
                            await other_ws.send(to_json(env))
                            print(f"📣 Relayed SERVER_ANNOUNCE to {other_id}")
                        except Exception as e:
                            print(f"❌ Failed to relay to {other_id}: {e}")

            else:
                print(f"ℹ️ Unhandled message type: {mtype}")

    except Exception as e:
        print("❌ Error in handler:", e)
    finally:
        if server_id and connected_servers.get(server_id) == websocket:
            print(f"⚠️ Connection closed for {server_id}")
            del connected_servers[server_id]


async def start_server():
    print("🌐 Fake Introducer running on ws://localhost:8765")
    async with websockets.serve(handle_join, "0.0.0.0", 8765):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(start_server())
