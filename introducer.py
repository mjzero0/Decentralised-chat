"""
SOCP Introducer Server (Bootstrap Node)

Implements the initial bootstrap logic for the Secure Overlay Chat Protocol (SOCP v1.3).
This Introducer receives SERVER_HELLO_JOIN requests, assigns unique server IDs,
and returns the known list of other bootstrap servers in the network.

Message Types Handled:
- SERVER_HELLO_JOIN → assigns server ID, returns SERVER_WELCOME

WebSocket listening address: ws://0.0.0.0:8765
"""

import asyncio
import websockets
import json
import time
import uuid

def now_ms():
    """Return current UNIX timestamp in milliseconds."""
    return int(time.time() * 1000)

def to_json(obj: dict) -> str:
    """
    Serialize a Python dictionary into a JSON string with newline.

    Args:
        obj: Dictionary to serialize.

    Returns:
        JSON string with newline appended.
    """
    return json.dumps(obj) + "\n"

# Mapping of connected servers
connected_servers = {}

# List of known bootstrap servers
bootstrap_servers = []

async def handle_join(websocket):
    """
    Handle incoming WebSocket connection from a joining server.

    Expects:
        - SERVER_HELLO_JOIN with host, port, and pubkey.
    
    Responds with:
        - SERVER_WELCOME including assigned ID and known bootstrap peers.

    Args:
        websocket: The incoming WebSocket connection.
    """
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
                
                # Ensure server_id uniqueness
                while server_id in connected_servers.keys():
                    server_id = str(uuid.uuid4())
                        
                connected_servers[server_id] = websocket
                
                temp_servers = bootstrap_servers.copy()
                
                bootstrap_servers.append({
                    "server_id": server_id,
                    "host": host,
                    "port": port,
                    "pubkey": pubkey
                })

                # Send SERVER_WELCOME
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
    """
    Start the Introducer WebSocket server on port 8765.

    Binds to 0.0.0.0 and runs the join handler loop indefinitely.
    """
    print("🌐 Introducer running on ws://localhost:8765")
    async with websockets.serve(handle_join, "0.0.0.0", 8765):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(start_server())
