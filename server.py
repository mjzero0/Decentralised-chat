import asyncio
import websockets
import uuid
import time
import json
import base64
import os
from common import make_envelope

# -------------------------
# CONFIGURATION
# -------------------------

INTRODUCER_HOST = "127.0.0.1"
INTRODUCER_PORT = 8765
INTRODUCER_ADDR = f"{INTRODUCER_HOST}:{INTRODUCER_PORT}"

# Your own externally accessible address and WS port (modify as needed or overwrite with environment variables)
MY_HOST = os.getenv("MY_HOST", "127.0.0.1")
MY_PORT = int(os.getenv("MY_PORT", "9001"))

# ---------- In-memory tables ----------
servers = {}         # server_id -> link (all other servers)
server_addrs = {}    # server_id -> (host, port) (all other servers)
local_users = {}     # user_id -> link (users belong to this server)
user_locations = {}  # user_id -> "local" | server_id (all users)
# Each Server MUST keep a short-term seen_ids cache for server-delivered frames (by (ts,from,to,hash(payload))) 
# and drop duplicates.
seen_ids = set()     # {(ts, from, to, sha256(payload))}

# -------------------------
# FAKE RSA PUBLIC KEY (normally base64url of DER bytes)
# -------------------------
FAKE_PUBKEY = base64.urlsafe_b64encode(b"my_fake_rsa_pubkey_4096_bytes").decode().rstrip("=")

# -------------------------
# ENVELOPE CREATOR
# -------------------------

def to_json(envelope: dict) -> str:
    return json.dumps(envelope) + "\n"

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
        # TODO: HOW DOES THIS SERVER KNOW THE CORRESPONDING SERVER TO THESE USERS???
        user_locations[user_id] = (client["host"], client["port"])
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
    
async def connect_to_other_server(host, port, server_id):
    uri = f"ws://{host}:{port}"
    try:
        ws = await websockets.connect(uri)
        servers[server_id] = ws
        print(f"🔗 Connected to server {server_id} at {host}:{port}")
    except Exception as e:
        print(f"❌ Failed to connect to {server_id}: {e}")
        
async def handle_server_announce(envelope: dict):
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

    # TODO: CHECK IF THIS IS CORRECT (Do we need to include pubkey or not???)
    server_addrs[from_id] = (host, int(port))

    print(f"🆕 Registered server {from_id} @ {host}:{port}")
    
    if from_id in servers:
        print(f"🔁 Already connected to {from_id}")
        return
    
    await connect_to_other_server(host, port, from_id)
    
async def handle_user_advertise(envelope):
    payload = envelope["payload"]
    user_id = payload["user_id"]
    server_id = payload["server_id"]

    # TODO: verify envelope["sig"] with pubkey of envelope["from"]

    user_locations[user_id] = server_id
    
    print(f"🌍 USER_ADVERTISE received: {user_id} is at {server_id}")
    print(f"📌 user_locations[{user_id}] = {server_id}")

    # TODO: Forward the message to other servers (gossip).
                
async def handle_user_hello(user_id, link):
    
    # if the user_id is in the memory
    if user_id in local_users or user_id in user_locations:
        error_msg = {
            "type": "ERROR",
            "code": "NAME_IN_USE",
            "reason": f"user_id '{user_id}' already exists"
        }
        await link.send(json.dumps(error_msg))
        print(f"❌ Duplicate user_id: {user_id}, rejected.")
        return
    
    local_users[user_id] = link
    user_locations[user_id] = "local"

    payload = {
        "user_id": user_id,
        "server_id": server_id,
        "meta": {}  # TODO: META needs to be done
    }

    envelope = {
        "type": "USER_ADVERTISE",
        "from": server_id,
        "to": "*",
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": ""  # TODO: 
    }
    
    print(f"📣 New user {user_id} connected.")

    # Broadcast to all servers
    for ws in servers.values():
        await ws.send(json.dumps(envelope))
        
    print(f"📡 Broadcasting USER_ADVERTISE for {user_id}")
        

async def broadcast_user_remove(user_id: str, server_id: str):
    payload = {
        "user_id": user_id,
        "server_id": server_id
    }

    envelope = {
        "type": "USER_REMOVE",
        "from": server_id,
        "to": "*",
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": ""  # TODO:
    }

    print(f"📤 Broadcasting USER_REMOVE for {user_id}")

    for id, ws in servers.items():
        try:
            await ws.send(json.dumps(envelope))
        except Exception as e:
            print(f"❌ Failed to send USER_REMOVE to {id}: {e}")
            
async def handle_user_remove(envelope):
    payload = envelope["payload"]
    user_id = payload["user_id"]
    target_server = payload["server_id"]

    # TODO: verify sig
    if user_locations.get(user_id) == target_server:
        del user_locations[user_id]
        print(f"🗑️ Removed {user_id} from user_locations")
    else:
        print(f"⚠️ Skipped removal of {user_id}: mismatch server_id")

    # TODO: Forward the removal to other Servers.

async def handle_user_deliver(from_user, to_user, payload):
    """
    Called when a MSG_DIRECT is destined for a local user.
    This function wraps it in USER_DELIVER and sends it to the user.
    """
    if to_user not in local_users:
        print(f"❌ Local user {to_user} not connected.")
        return

    user_payload = {
        "ciphertext": payload["ciphertext"],
        "sender": from_user,
        "sender_pub": payload["sender_pub"],
        "content_sig": payload["content_sig"]
    }

    envelope = make_envelope(
        msg_type="USER_DELIVER",
        sender=server_id,
        receiver=to_user,
        payload=user_payload
    )
    # envelope["sig"] = sign_payload(envelope["payload"])
    envelope["sig"] = "" # TODO:
    
    ws = local_users[to_user]
    await ws.send(json.dumps(envelope))
    print(f"✅ USER_DELIVER sent to {to_user}")


async def make_server_deliver(envelope: dict, to_server: str):
    
    payload = envelope["payload"]
    
    user_payload = {
        "user_id": envelope["to"],
        "ciphertext": payload["ciphertext"],
        "sender": envelope["from"],
        "sender_pub": payload["sender_pub"],
        "content_sig": payload["content_sig"]
    }

    envelope = {
        "type": "SERVER_DELIVER",
        "from": server_id,
        "to": to_server,
        "payload": user_payload
    }
    # envelope["sig"] = sign_payload(envelope["payload"])
    envelope["sig"] = "" # TODO:
    return envelope

async def handle_server_deliver(envelope):
    user_id = envelope["to"]
    to_server = user_locations.get(user_id)

    # deliver to local user link
    if to_server == "local":
        print(f"❌ Local user connected.")
        return
    
    # deliver to other server
    if isinstance(to_server, str) and to_server in servers:
        new_envelope = make_server_deliver(envelope, to_server)
        print(f"🔁 Forwarding to server {to_server}")
        await servers[to_server].send(json.dumps(new_envelope))
    else:
        print(f"❌ USER_NOT_FOUND: {user_id} (cannot route)")
        
async def handle_msg_direct(envelope):
    from_user = envelope["from"]
    to_user = envelope["to"]
    payload = envelope["payload"]
    if user_locations.get(to_user) == "local":
        await handle_user_deliver(from_user, to_user, payload)
    else:
        await handle_server_deliver(envelope)
            
async def handle_connection(websocket):
    try:
        while True:
            raw = await websocket.recv()
            envelope = json.loads(raw)
            mtype = envelope.get("type")

            if mtype == "USER_HELLO":
                user_id = envelope["from"]
                await handle_user_hello(user_id, websocket)

            elif mtype == "USER_ADVERTISE":
                await handle_user_advertise(envelope)

            elif mtype == "MSG_DIRECT":
                await handle_msg_direct(envelope)

            elif mtype == "USER_REMOVE":
                await handle_user_remove(envelope)

            else:
                print(f"📩 Unknown or unhandled message type: {mtype}")

    except Exception as e:
        print(f"⚠️ Connection closed or error: {e}")

        # find the user who has disconnected
        disconnected_user = None
        for uid, link in list(local_users.items()):
            if link == websocket:
                disconnected_user = uid
                break

        if disconnected_user:
            del local_users[disconnected_user]
            user_locations.pop(disconnected_user, None)

            await broadcast_user_remove(disconnected_user, server_id)
            print(f"👋 User {disconnected_user} disconnected and removed.")


async def join_network():
    try:
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

                # TODO: how does this server connect to other servers???
                elif mtype == "SERVER_ANNOUNCE":
                    await handle_server_announce(msg)

                else:
                    print(f"!!! Unhandled message type: {mtype} !!!")
    
    except websockets.exceptions.ConnectionClosedOK:
        print("✅ Introducer closed connection (1000): normal after welcome.")
                
async def main():
    
    print(f"🚀 Starting WebSocket server on {MY_HOST}:{MY_PORT}")
    ws_server = await websockets.serve(handle_connection, MY_HOST, MY_PORT)
    
    await join_network()
    

if __name__ == "__main__":
    asyncio.run(main())
