import asyncio
import websockets
import json
import time
import os
import uuid

from common import (
    make_envelope,
    make_signed_envelope,
    verify_transport_sig,
    load_private_key_pem,
    public_key_b64u_from_private,
    frame_fingerprint,   # for de-dup
)

# -------------------------
# CONFIGURATION
# -------------------------

INTRODUCER_HOST = "10.13.101.11"
INTRODUCER_PORT = 8765
INTRODUCER_ADDR = f"{INTRODUCER_HOST}:{INTRODUCER_PORT}"

# Bind to all interfaces by default so teammates can connect over LAN.
MY_HOST = os.getenv("MY_HOST", "10.13.101.11")
MY_PORT = int(os.getenv("MY_PORT", "9001"))

# ---------- In-memory tables ----------
servers = {}           # server_id -> websocket (server↔server links)
server_addrs = {}      # server_id -> (host, port)
server_pubkeys = {}    # server_id -> pubkey_b64u (learned via SERVER_ANNOUNCE)
local_users = {}       # local user table: user_id -> {"ws": websocket, "pubkey": str}
user_locations = {}    # user_id -> "local" | server_id
seen_ids = set()       # {(ts, from, to, sha256(payload))}
user_pubkeys = {}       # users from other server's public key

# Assigned after SERVER_WELCOME
server_id = None

# ---------- Server RSA keypair ----------
with open("server_priv.pem", "rb") as f:
    server_priv = load_private_key_pem(f.read())
server_pub_b64u = public_key_b64u_from_private(server_priv)

# -------------------------
# UTIL
# -------------------------

def to_json(envelope: dict) -> str:
    return json.dumps(envelope) + "\n"

def dedup_or_remember(env: dict) -> bool:
    """Return True if we've seen this envelope before (drop it), else remember it and return False."""
    fp = frame_fingerprint(env)
    if fp in seen_ids:
        return True
    seen_ids.add(fp)
    # Optional: keep the set from growing forever (very small TTL-like cleanup)
    if len(seen_ids) > 5000:
        # naive prune: drop oldest ~1/3 by recreating set from last 2/3 (cheap enough here)
        seen_ids_copy = list(seen_ids)[int(len(seen_ids) * (1/3)):]
        seen_ids.clear()
        seen_ids.update(seen_ids_copy)
    return False

# Broadcast only within one server
async def broadcast(msg):
    dead = []
    for uid, info in local_users.items():
        payload = msg.get("payload")
        if uid == payload["user_id"]:
            continue
        try:
            await info["ws"].send(json.dumps(msg))
        except Exception:
            dead.append(uid)
    for uid in dead:
        del local_users[uid]

async def handle_user_hello(websocket, env):
    user_id = env["from"]
    payload = env["payload"]
    pubkey = payload.get("pubkey")
    username = payload.get("username")

    # check duplicate
    if user_id in local_users or user_id in user_locations:
        error_msg = make_signed_envelope(
            "ERROR", server_id, user_id,
            {"code": "NAME_IN_USE", "detail": f"user_id {user_id} already exists"},
            server_priv
        )
        await websocket.send(json.dumps(error_msg))
        print(f"❌ Duplicate user_id: {user_id}, rejected.")
        return

    local_users[user_id] = {"ws": websocket, "pubkey": pubkey, "username": username}
    user_locations[user_id] = "local"
    print(f"👋 New user {username} ({user_id}) connected.")

    # broadcast local users to the new server
    for uid, info in local_users.items():
        if uid == user_id: 
            continue
        msg = make_signed_envelope(
            "USER_ADVERTISE", server_id, user_id,
            {"user_id": uid, "server_id": server_id, "meta": {"username": info["username"], "pubkey": info["pubkey"]}},
            server_priv
        )
        await websocket.send(json.dumps(msg))

    advertise_payload = {
        "user_id": user_id,
        "server_id": server_id,
        "meta": {"username": username, "pubkey": pubkey}
    }
    advertise = make_signed_envelope("USER_ADVERTISE", server_id, "*", advertise_payload, server_priv)

    # broadcast to local users
    await broadcast(advertise)
    print(f"📡 Broadcasted USER_ADVERTISE for {user_id} to local users")

    # gossip to other servers
    for sid, ws in servers.items():
        if sid == server_id:
            continue
        try:
            await ws.send(json.dumps(advertise))
        except Exception as e:
            print(f"❌ Gossip to {sid} failed: {e}")

    print(f"📡 Gossip USER_ADVERTISE for {user_id} to {len(servers)} servers")


# async def handle_msg_direct(env):
#     target = env["to"]
#     if target in local_users:
#         deliver = {
#             "type": "USER_DELIVER",
#             "from": "server",
#             "to": target,
#             "ts": env["ts"],
#             "payload": env["payload"],
#             "sig": ""
#         }
        
async def handle_user_deliver(from_user, to_user, payload):
    if to_user not in local_users:
        print(f"❌ Local user {to_user} not connected.")
        return

    user_payload = {
        "ciphertext": payload["ciphertext"],
        "sender": from_user,
        "sender_pub": payload["sender_pub"],
        "content_sig": payload["content_sig"],
    }
    env = make_signed_envelope("USER_DELIVER", server_id, to_user, user_payload, server_priv)
    await local_users[to_user]["ws"].send(json.dumps(env))
    print(f"✅ USER_DELIVER sent to {to_user}")

def make_server_deliver(envelope: dict, to_server: str):
    payload = envelope["payload"]
    user_payload = {
        "user_id": envelope["to"],
        "ciphertext": payload["ciphertext"],
        "sender": envelope["from"],
        "sender_pub": payload["sender_pub"],
        "content_sig": payload["content_sig"],
    }
    return make_signed_envelope("SERVER_DELIVER", server_id, to_server, user_payload, server_priv)

async def handle_server_deliver(envelope):
    # Forward to the server where the recipient lives (or deliver locally)
    user_id = envelope["to"]
    dest = user_locations.get(user_id)

    if dest == "local":
        print(f"ℹ️ SERVER_DELIVER reached home server; handing to user.")
        await handle_user_deliver(envelope["payload"]["sender"], user_id, envelope["payload"])
        return

    if isinstance(dest, str) and dest in servers:
        new_env = make_server_deliver(envelope, dest)
        if not dedup_or_remember(new_env):
            print(f"🔁 Forwarding to server {dest}")
            await servers[dest].send(json.dumps(new_env))
    else:
        print(f"❌ USER_NOT_FOUND: {user_id} (cannot route)")

async def handle_msg_direct(envelope):
    # (Optional) verify transport sig from users later once you store user pubkeys from USER_HELLO
    from_user = envelope["from"]
    to_user = envelope["to"]
    payload = envelope["payload"]
    if user_locations.get(to_user) == "local":
        await handle_user_deliver(from_user, to_user, payload)
    else:
        await handle_server_deliver(envelope)  
        
async def make_server_hello_join(_temp_server_id: str, host: str, port: int) -> dict:
    # HELLO is allowed unsigned per your notes
    _temp_server_id = str(uuid.uuid4())
    return {
        "type": "SERVER_HELLO_JOIN",
        "from": _temp_server_id,
        "to": f"{host}:{port}",
        "ts": int(time.time() * 1000),
        "payload": {"host": MY_HOST, "port": MY_PORT, "pubkey": server_pub_b64u},
        "sig": ""
    }
    
async def make_server_announce(to_id: str, host: str, port: int, pubkey_b64u: str) -> dict:
    return make_signed_envelope(
        "SERVER_ANNOUNCE", server_id, to_id,
        {"host": host, "port": port, "pubkey": pubkey_b64u},
        server_priv,
    )

# -------------------------
# INTRODUCER HANDSHAKE
# -------------------------

async def connect_to_other_server(host, port, _server_id):
    uri = f"ws://{host}:{port}"
    try:
        ws = await websockets.connect(uri)
        servers[_server_id] = ws # connect to the new server
        print(f"🔗 Connected to server {_server_id} at {uri}")
        
        await ws.send(to_json(await make_server_hello_link(_server_id)))
        print(f"✅ Send SERVER_HELLO_LINK to server id: {_server_id}.")

        if server_id:
            announce = await make_server_announce(_server_id, MY_HOST, MY_PORT, server_pub_b64u)
            await ws.send(to_json(announce))
            print(f"📣 Sent SERVER_ANNOUNCE for {server_id} ({MY_HOST}:{MY_PORT})")

    except Exception as e:
        print(f"❌ Failed to connect to {_server_id}: {e}")

async def handle_server_welcome(envelope: dict):
    payload = envelope["payload"]
    global server_id
    server_id = payload["assigned_id"]
    print(f"✅ Assigned server_id: {server_id}")

    introducer_id = envelope["from"]
    print(f"📡 Introducer is {introducer_id}")

    # If introducer relays any currently-known clients:
    for client in payload.get("clients", []):
        if client == []:
            break
        else:
            # this user_id is the server_id of other servers
            user_id = client["server_id"]
            server_addrs[user_id] = (client["host"], client["port"])
            server_pubkeys[user_id] = client["pubkey"]
            print(f"📥 Learned server {user_id} is on {(client['host'], client['port'])}")
        
    for key, addr in server_addrs.items():
        host, port = addr
        await connect_to_other_server(host, port, key)
        

# -------------------------
# SERVER↔SERVER LINKS
# -------------------------

async def make_server_hello_link(to_sid: str) -> dict:
    return {
        "type": "SERVER_HELLO_LINK",
        "from": server_id,
        "to": to_sid,
        "ts": int(time.time() * 1000),
        "payload": {
            "host": MY_HOST,
            "port": MY_PORT,
            "pubkey": server_pub_b64u,
        },
        "sig": ""  # TODO: SIGN
    }


async def handle_server_announce(envelope: dict):
    # Verify this ANNOUNCE if we already have sender's pubkey.
    from_id = envelope.get("from")
    payload = envelope.get("payload", {})
    host = payload.get("host")
    port = payload.get("port")
    pubkey = payload.get("pubkey")

    if server_id and from_id == server_id:
        return
    if not (from_id and host and port and pubkey):
        print(f"⚠️ Malformed SERVER_ANNOUNCE: {envelope}")
        return
    
    sig = envelope.get("sig")
    if from_id in server_pubkeys:
        pubkey = server_pubkeys[from_id]
        # if not verify_transport_sig(pubkey, envelope["payload"], sig):
        if not verify_transport_sig(envelope, pubkey):
            print(f"❌ Invalid signature on SERVER_ANNOUNCE from {from_id}")
            return

    # Trust-on-first-use: save pubkey for future verifications
    server_addrs[from_id] = (host, int(port))
    server_pubkeys[from_id] = pubkey
    print(f"🆕 Registered server {from_id} @ {host}:{port}")

# -------------------------
# PRESENCE / GOSSIP
# -------------------------

async def handle_user_advertise(envelope):
    if dedup_or_remember(envelope):
        return

    # If this came from another server and we know its key, verify it
    sender = envelope.get("from")
    if sender in server_pubkeys:
        if not verify_transport_sig(envelope, server_pubkeys[sender]):
            print(f"❌ Invalid signature on USER_ADVERTISE from {sender}")
            return

    payload = envelope["payload"]
    user_id = payload["user_id"]
    src_server = payload["server_id"]

    user_locations[user_id] = src_server
    print(f"🌍 USER_ADVERTISE received: {user_id} is at {src_server}")

    # Gossip forward to other servers (except origin if we have a direct link to it)
    for sid, ws in servers.items():
        if sid == server_id:
            continue
        try:
            await ws.send(json.dumps(envelope))
        except Exception as e:
            print(f"❌ Gossip USER_ADVERTISE to {sid} failed: {e}")
            
async def broadcast_user_remove(user_id: str, _server_id: str):
    payload = {"user_id": user_id, "server_id": _server_id}
    envelope = make_signed_envelope("USER_REMOVE", _server_id, "*", payload, server_priv)
    print(f"📤 Broadcasting USER_REMOVE for {user_id}")

    for sid, ws in servers.items():
        try:
            await ws.send(json.dumps(envelope))
        except Exception as e:
            print(f"❌ Failed to send USER_REMOVE to {sid}: {e}")
            
async def handle_user_remove(envelope):
    if dedup_or_remember(envelope):
        return

    sender = envelope.get("from")
    if sender in server_pubkeys:
        if not verify_transport_sig(envelope, server_pubkeys[sender]):
            print(f"❌ Invalid signature on USER_REMOVE from {sender}")
            return

    payload = envelope["payload"]
    user_id = payload["user_id"]
    target_server = payload["server_id"]

    if user_locations.get(user_id) == target_server:
        del user_locations[user_id]
        print(f"🗑️ Removed {user_id} from user_locations")
    else:
        print(f"⚠️ Skipped removal of {user_id}: mismatch server_id")

    # Gossip forward
    for sid, ws in servers.items():
        try:
            await ws.send(json.dumps(envelope))
        except Exception as e:
            print(f"❌ Gossip USER_REMOVE to {sid} failed: {e}")

                
async def handle_connection(websocket):
    try:
        while True:
            raw = await websocket.recv()
            envelope = json.loads(raw)
            mtype = envelope.get("type")

            # # Drop duplicate frames early
            # if mtype in ("USER_ADVERTISE", "USER_REMOVE", "SERVER_DELIVER") and dedup_or_remember(envelope):
            #     continue

            if mtype == "USER_HELLO":
                # user_id = envelope["from"]
                await handle_user_hello(websocket, envelope)
                
            elif mtype == "SERVER_HELLO_LINK":
                
                sid = envelope["from"]
                host = envelope["payload"]["host"]
                port = envelope["payload"]["port"]
                
                uri = f"ws://{host}:{port}"
                ws = await websockets.connect(uri)
                print(f"🔗 Connected to server {sid} at {uri}")
                servers[sid] = ws

            elif mtype == "USER_ADVERTISE":
                await handle_user_advertise(envelope)

            elif mtype == "MSG_DIRECT":
                await handle_msg_direct(envelope)

            elif mtype == "USER_REMOVE":
                await handle_user_remove(envelope)

            elif mtype == "SERVER_ANNOUNCE":
                await handle_server_announce(envelope)

            else:
                print(f"📩 Unknown or unhandled message type: {mtype}")
            
    except Exception as e:
        print(f"❌ Client handler error: {e}")
        
    finally:
        # Remove user if disconnected
        for uid, info in list(local_users.items()):
            if info["ws"] == websocket:
                del local_users[uid]
                print(f"👋 User {uid} disconnected.")
                user_locations.pop(uid, None)
                await broadcast_user_remove(uid, server_id)
                # Broadcast removal
                rm = {
                    "type": "USER_REMOVE",
                    "from": "server",
                    "to": "*",
                    "ts": int(time.time() * 1000),
                    "payload": {"user_id": uid},
                    "sig": ""
                }
                await broadcast(rm)

# -------------------------
# BOOTSTRAP
# -------------------------

async def join_network():
    try:
        hello = await make_server_hello_join(server_id, INTRODUCER_HOST, INTRODUCER_PORT)

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
                    await handle_server_welcome(msg)

                else:
                    print(f"!!! Unhandled message type from introducer: {mtype} !!!")

    except websockets.exceptions.ConnectionClosedOK:
        print("✅ Introducer closed connection (1000): normal after welcome.")
        
async def main():
    print(f"🚀 Starting WebSocket server on {MY_HOST}:{MY_PORT}")
    ws_server = await websockets.serve(handle_connection, MY_HOST, MY_PORT)
    await join_network()


if __name__ == "__main__":
    asyncio.run(main())
