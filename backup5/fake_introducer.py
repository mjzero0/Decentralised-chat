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

connected_servers = {} # server_id -> websocket
bootstrap_servers = [] # server_id -> (host, port, pubkey)

async def handle_join(websocket):
    server_id = None
    try:
        async for msg in websocket:
            env = json.loads(msg)
            mtype = env["type"]

            if mtype == "SERVER_HELLO_JOIN":
                server_id = env["from"]
                pubkey = env["payload"]["pubkey"]
                host = env["payload"]["host"]
                port = env["payload"]["port"]
                
                # server_id is checked within network to verify its uniqueness. If it is, return same ID, 
                # otherwise return new unique ID
                while server_id in connected_servers.keys():
                    server_id = str(uuid.uuid4())
                        
                connected_servers[server_id] = websocket
                
                temp_servers = bootstrap_servers.copy()
                
                bootstrap_servers.append({"server_id": server_id, "host": host, "port": port, "pubkey": pubkey})

                # Send WELCOME
                welcome = {
                    "type": "SERVER_WELCOME",
                    "from": "introducer-0000-0000",
                    "to": server_id,
                    "ts": now_ms(),
                    "payload": {
                        "assigned_id": server_id,
                        "clients": temp_servers
                    },
                    "sig": ""
                }
                await websocket.send(to_json(welcome))
                print(f"📤 Sent SERVER_WELCOME to {server_id}")

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
