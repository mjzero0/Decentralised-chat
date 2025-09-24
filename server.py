import asyncio
import websockets
import uuid
import time
import json
import os

from common import (
    make_envelope,
    make_signed_envelope,
    verify_transport_sig,
    load_private_key_pem,
    public_key_b64u_from_private,
)

# -------------------------
# CONFIGURATION
# -------------------------

INTRODUCER_HOST = "127.0.0.1"
INTRODUCER_PORT = 8765
INTRODUCER_ADDR = f"{INTRODUCER_HOST}:{INTRODUCER_PORT}"

MY_HOST = os.getenv("MY_HOST", "127.0.0.1")
MY_PORT = int(os.getenv("MY_PORT", "9001"))

# ---------- In-memory tables ----------
servers = {}         # server_id -> link
server_addrs = {}    # server_id -> (host, port)
local_users = {}     # user_id -> link
user_locations = {}  # user_id -> "local" | server_id
seen_ids = set()     # for duplicate suppression

# ---------- Server RSA keypair ----------
with open("server_priv.pem", "rb") as f:
    server_priv = load_private_key_pem(f.read())
server_pub_b64u = public_key_b64u_from_private(server_priv)

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
            "pubkey": server_pub_b64u
        },
        "sig": ""  # allowed empty in HELLO
    }

def handle_server_welcome(envelope: dict):
    payload = envelope["payload"]
    assigned_id = payload["assigned_id"]

    global server_id
    server_id = assigned_id
    print(f"✅ Assigned server_id: {server_id}")

    introducer_id = envelope["from"]
    print(f"📡 Introducer is {introducer_id}")

    for client in payload.get("clients", []):
        user_id = client["user_id"]
        user_locations[user_id] = (client["host"], client["port"])
        print(f"📥 Learned user {user_id} is on {(client['host'], client['port'])}")

def make_server_announce(from_id: str, host: str, port: int, pubkey_b64u: str) -> dict:
    return make_signed_envelope(
        "SERVER_ANNOUNCE",
        from_id,
        "*",
        {"host": host, "port": port, "pubkey": pubkey_b64u},
        server_priv,
    )

async def connect_to_other_server(host, port, server_id):
    uri = f"ws://{host}:{port}"
    try:
        ws = await websockets.connect(uri)
        servers[server_id] = ws
        print(f"🔗 Connected to server {server_id} at {host}:{port}")
    except Exception as e:
        print(f"❌ Failed to connect to {server_id}: {e}")

async def handle_server_announce(envelope: dict):
    from_id = envelope.get("from")
    payload = envelope.get("payload", {})
    host = payload.get("host")
    port = payload.get("port")
    pubkey = payload.get("pubkey")

    if server_id and from_id == server_id:
        return

    if not (from_id and host and port):
        print(f"⚠️ Malformed SERVER_ANNOUNCE: {envelope}")
        return

    server_addrs[from_id] = (host, int(port))
    print(f"🆕 Registered server {from_id} @ {host}:{port}")

    if from_id in servers:
        print(f"🔁 Already connected to {from_id}")
        return

    await connect_to_other_server(host, port, from_id)

async def handle_user_advertise(envelope):
    payload = envelope["payload"]
    user_id = payload["user_id"]
    src_server = payload["server_id"]

    # TODO: verify envelope["sig"] with pubkey of envelope["from"]

    user_locations[user_id] = src_server
    print(f"🌍 USER_ADVERTISE received: {user_id} is at {src_server}")
    print(f"📌 user_locations[{user_id}] = {src_server}")

    # TODO: Gossip forward

async def handle_user_hello(user_id, link):
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

    payload = {"user_id": user_id, "server_id": server_id, "meta": {}}
    envelope = make_signed_envelope("USER_ADVERTISE", server_id, "*", payload, server_priv)

    print(f"📣 New user {user_id} connected.")

    for ws in servers.values():
        await ws.send(json.dumps(envelope))
    print(f"📡 Broadcasting USER_ADVERTISE for {user_id}")

async def broadcast_user_remove(user_id: str, server_id: str):
    payload = {"user_id": user_id, "server_id": server_id}
    envelope = make_signed_envelope("USER_REMOVE", server_id, "*", payload, server_priv)

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

    if user_locations.get(user_id) == target_server:
        del user_locations[user_id]
        print(f"🗑️ Removed {user_id} from user_locations")
    else:
        print(f"⚠️ Skipped removal of {user_id}: mismatch server_id")

    # TODO: Forward removal

async def handle_user_deliver(from_user, to_user, payload):
    if to_user not in local_users:
        print(f"❌ Local user {to_user} not connected.")
        return

    user_payload = {
        "ciphertext": payload["ciphertext"],
        "sender": from_user,
        "sender_pub": payload["sender_pub"],
        "content_sig": payload["content_sig"]
    }

    envelope = make_signed_envelope("USER_DELIVER", server_id, to_user, user_payload, server_priv)

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
    return make_signed_envelope("SERVER_DELIVER", server_id, to_server, user_payload, server_priv)

async def handle_server_deliver(envelope):
    user_id = envelope["to"]
    to_server = user_locations.get(user_id)

    if to_server == "local":
        print(f"❌ Local user connected.")
        return

    if isinstance(to_server, str) and to_server in servers:
        new_env = await make_server_deliver(envelope, to_server)
        print(f"🔁 Forwarding to server {to_server}")
        await servers[to_server].send(json.dumps(new_env))
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

            while True:
                raw = await websocket.recv()
                msg = json.loads(raw)
                mtype = msg.get("type")

                if mtype == "SERVER_WELCOME":
                    handle_server_welcome(msg)
                    if server_id:
                        announce = make_server_announce(server_id, MY_HOST, MY_PORT, server_pub_b64u)
                        await websocket.send(to_json(announce))
                        print(f"📣 Sent SERVER_ANNOUNCE for {server_id} ({MY_HOST}:{MY_PORT})")
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
