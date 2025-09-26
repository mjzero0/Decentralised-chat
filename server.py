import asyncio
import websockets
import json
import time
import os

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

INTRODUCER_HOST = "127.0.0.1"
INTRODUCER_PORT = 8765
INTRODUCER_ADDR = f"{INTRODUCER_HOST}:{INTRODUCER_PORT}"

# Bind to all interfaces by default so teammates can connect over LAN.
MY_HOST = os.getenv("MY_HOST", "0.0.0.0")
MY_PORT = int(os.getenv("MY_PORT", "9001"))

# ---------- In-memory tables ----------
servers = {}           # server_id -> websocket (server↔server links)
server_addrs = {}      # server_id -> (host, port)
server_pubkeys = {}    # server_id -> pubkey_b64u (learned via SERVER_ANNOUNCE)
local_users = {}       # local user table: user_id -> {"ws": websocket, "pubkey": str}
user_locations = {}    # user_id -> "local" | server_id
seen_ids = set()       # {(ts, from, to, sha256(payload))}

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

async def broadcast(msg):
    dead = []
    for uid, info in local_users.items():
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

    local_users[user_id] = {"ws": websocket, "pubkey": pubkey, "username": username}
    print(f"👋 New user {username} ({user_id}) connected.")

    now = int(time.time() * 1000)

    # Tell newcomer about existing users
    for uid, info in list(local_users.items()):
        if uid == user_id: continue
        advertise_existing = {
            "type": "USER_ADVERTISE",
            "from": "server",
            "to": user_id,
            "ts": now,
            "payload": {
                "user_id": uid,
                "username": info.get("username"),
                "pubkey": info.get("pubkey")
            },
            "sig": ""
        }
        await websocket.send(json.dumps(advertise_existing))

    # Broadcast newcomer
    advertise_new = {
        "type": "USER_ADVERTISE",
        "from": "server",
        "to": "*",
        "ts": now,
        "payload": {"user_id": user_id, "username": username, "pubkey": pubkey},
        "sig": ""
    }

    await broadcast(advertise_new)


async def handle_msg_direct(env):
    target = env["to"]
    if target in local_users:
        deliver = {
            "type": "USER_DELIVER",
            "from": "server",
            "to": target,
            "ts": env["ts"],
            "payload": env["payload"],
            "sig": ""
        }
=======

def make_server_announce(from_id: str, host: str, port: int, pubkey_b64u: str) -> dict:
    return make_signed_envelope(
        "SERVER_ANNOUNCE", from_id, "*",
        {"host": host, "port": port, "pubkey": pubkey_b64u},
        server_priv,
    )

# -------------------------
# INTRODUCER HANDSHAKE
# -------------------------

def handle_server_welcome(envelope: dict):
    payload = envelope["payload"]
    server_id = payload["assigned_id"]
    print(f"✅ Assigned server_id: {server_id}")

    introducer_id = envelope["from"]
    print(f"📡 Introducer is {introducer_id}")

    # If introducer relays any currently-known clients:
    for client in payload.get("clients", []):
        user_id = client["user_id"]
        user_locations[user_id] = (client["host"], client["port"])
        print(f"📥 Learned user {user_id} is on {(client['host'], client['port'])}")
        
    # for other_server in payload.get("servers", []):
    #     other_server_id = other_server["server_id"]
    #     server_addrs[other_server_id] = (other_server["host"], other_server["port"])
    #     server_pubkeys[other_server_id] = other_server["pubkey"]
        

# -------------------------
# SERVER↔SERVER LINKS
# -------------------------

async def handle_send_server_info(envelope):
    from_id = envelope.get("from")
    payload = envelope.get("payload", {})
    host = payload.get("host")
    port = payload.get("port")
    pubkey = payload.get("pubkey")

    if server_id and from_id == server_id:
        return
    if not (from_id and host and port and pubkey):
        print(f"⚠️ Malformed SEND_SERVER_INFO: {envelope}")
        return

    server_addrs[from_id] = (host, int(port))
    server_pubkeys[from_id] = pubkey
    print(f"🆕 Registered server {from_id} @ {host}:{port}")

    if from_id in servers:
        print(f"🔁 Already connected to {from_id}")
        return

    uri = f"ws://{host}:{port}"
    try:
        ws = await websockets.connect(uri)
        servers[from_id] = ws # connect to the new server
        print(f"🔗 Connected to server {from_id} at {uri}")

    except Exception as e:
        print(f"❌ Failed to connect to {from_id}: {e}")
        

async def handle_send_user_info(envelope):
    payload = envelope.get("payload", {})
    user_id = payload.get("user_id")
    connected_server_id = payload.get("connected_server_id")
    # pubkey = payload.get("pubkey") TODO: pubkey

    if server_id and connected_server_id == server_id:
        return
    # TODO: uncomment the following lines
    # if not (connected_server_id and pubkey):
    #     print(f"⚠️ Malformed SEND_USER_INFO: {envelope}")
    #     return

    user_locations[user_id] = connected_server_id
    # TODO: user_pubkeys[user_id] = pubkey
    print(f"🆕 Registered user {user_id} at {connected_server_id}")

        
async def connect_to_other_server(host, port, _server_id):
    uri = f"ws://{host}:{port}"
    try:
        ws = await websockets.connect(uri)
        servers[_server_id] = ws # connect to the new server
        print(f"🔗 Connected to server {_server_id} at {uri}")
        # Send all server addresses I know
        for sid, (h, p) in server_addrs.items():
            if sid == _server_id:  # skip the target itself
                continue
            pubkey = server_pubkeys.get(sid, "")
            server_info = {
                "type": "SEND_SERVER_INFO",
                "from": server_id,
                "to": _server_id,
                "ts": int(time.time() * 1000),
                "payload": {
                    "host": h,
                    "port": p,
                    "pubkey": pubkey
                },
                "sig": ""  # TODO: add signiture??
            }
            await ws.send(to_json(server_info))
            print(f"📨 Sent SEND_SERVER_INFO (about {sid}) to {_server_id}")

        # Send all user information I know
        # TODO: WE NEED TO SEND USER PUBLIC KEY AS WELL
        for user_id, connected_server_id in user_locations.items():
            user_info = {
                "type": "SEND_USER_INFO",
                "from": server_id,
                "to": _server_id,
                "ts": int(time.time() * 1000),
                "payload": {
                    "user_id": user_id,
                    "connected_server_id": connected_server_id
                    # "pubkey": pubkey
                },
                "sig": ""  # TODO: add signiture??
            }
            await ws.send(to_json(user_info))
            print(f"📨 Sent SEND_USER_INFO for {user_id} to {_server_id}")

    except Exception as e:
        print(f"❌ Failed to connect to {_server_id}: {e}")


async def handle_server_announce(envelope: dict):
    # (Optional) verify this ANNOUNCE if we already have sender's pubkey.
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

    # Trust-on-first-use: save pubkey for future verifications
    server_addrs[from_id] = (host, int(port))
    server_pubkeys[from_id] = pubkey
    print(f"🆕 Registered server {from_id} @ {host}:{port}")

    if from_id in servers:
        print(f"🔁 Already connected to {from_id}")
        return

    await connect_to_other_server(host, port, from_id)

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
            await local_users[target]["ws"].send(json.dumps(deliver))
            print(f"✅ USER_DELIVER sent to {target}")
        except Exception as e:
            print(f"❌ Failed to deliver to {target}: {e}")

async def handle_client(websocket):
    try:
        async for raw in websocket:
            env = json.loads(raw)
            mtype = env.get("type")

            if mtype == "USER_HELLO":
                await handle_user_hello(websocket, env)
                
            elif mtype == "MSG_DIRECT":
                await handle_msg_direct(env)

            elif mtype == "USER_REMOVE":
                await handle_user_remove(env)

            elif mtype == "SERVER_ANNOUNCE":
                await handle_server_announce(env)
                
            elif mtype == "SEND_SERVER_INFO":
                await handle_send_server_info(env)
                
            elif mtype == "SEND_USER_INFO":
                await handle_send_user_info(env)
           
            else:
                print(f"ℹ️ Unhandled msg type {mtype}")

    except Exception as e:
        print(f"❌ Client handler error: {e}")
    finally:
        # Remove user if disconnected
        for uid, info in list(local_users.items()):
            if info["ws"] == websocket:
                del local_users[uid]
                print(f"👋 User {uid} disconnected.")
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
                

async def main():
    async with websockets.serve(handle_client, "0.0.0.0", 9001):
        print("🌐 Server running on ws://0.0.0.0:9001")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
