import asyncio
import websockets
import json
import time
import os
import hmac
import hashlib
import uuid
import base64

from cryptography.hazmat.primitives import serialization
from common import (
    public_key_b64u_from_private,
    sign_transport_payload,
    verify_transport_sig,
    load_private_key_pem,
    frame_fingerprint,
    make_signed_envelope
)

# -------------------------
# CONFIGURATION
# -------------------------

INTRODUCER_HOST = "127.0.0.1"
INTRODUCER_PORT = 8765
INTRODUCER_ADDR = f"{INTRODUCER_HOST}:{INTRODUCER_PORT}"

MY_HOST = os.getenv("MY_HOST", "127.0.0.1")
MY_PORT = int(os.getenv("MY_PORT", "9001"))

# -------------------------
# SERVER KEY
# -------------------------
SERVER_PRIVKEY = None
SERVER_PUB_B64U = None

def load_server_keys(priv_path="server_priv.pem"):
    global SERVER_PRIVKEY, SERVER_PUB_B64U
    with open(priv_path, "rb") as f:
        pem = f.read()
    SERVER_PRIVKEY = serialization.load_pem_private_key(pem, password=None)
    SERVER_PUB_B64U = public_key_b64u_from_private(SERVER_PRIVKEY)
    print("🔑 Loaded server key pair.")

# -------------------------
# DB (for user register/login)
# -------------------------
DB_FILE = "users_db.json"

def load_db():
    if not os.path.exists(DB_FILE):
        return {"users": {}}
    with open(DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_db(db):
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, DB_FILE)

db = load_db()

# -------------------------
# In-memory tables (§5.2)
# -------------------------
servers = {}           # server_id -> websocket
server_addrs = {}      # server_id -> (host, port)
server_pubkeys = {}    # server_id -> pubkey_b64u
local_users = {}       # user_id -> {"ws": websocket, "pubkey": str, "username": str}
user_locations = {}    # user_id -> "local" | server_id
pending_auth = {}      # websocket -> {"username": str, "nonce": bytes}
seen_ids = set()      

server_id = None  # assigned after SERVER_WELCOME

# -------------------------
# UTILS
# -------------------------
def now_ms():
    return int(time.time() * 1000)

def base64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

async def sign_and_send(ws, msg):
    if "payload" not in msg:
        msg["payload"] = {}
    if SERVER_PRIVKEY:
        try:
            msg["sig"] = sign_transport_payload(SERVER_PRIVKEY, msg["payload"])
        except Exception as e:
            print("❌ sign_transport_payload failed:", e)
            msg["sig"] = ""
    else:
        msg["sig"] = ""
    await ws.send(json.dumps(msg))

def dedup_or_remember(env: dict) -> bool:
    fp = frame_fingerprint(env)
    if fp in seen_ids:
        return True
    seen_ids.add(fp)
    if len(seen_ids) > 5000:
        seen_ids_copy = list(seen_ids)[int(len(seen_ids) * (1/3)):]
        seen_ids.clear()
        seen_ids.update(seen_ids_copy)
    return False

# -------------------------
# BROADCAST
# -------------------------
async def broadcast(msg):
    dead = []
    for uid, info in local_users.items():
        payload = msg.get("payload")
        if uid == payload["user_id"]:
            continue
        try:
            await sign_and_send(info["ws"], msg)
        except Exception:
            dead.append(uid)
    for uid in dead:
        local_users.pop(uid, None)

# -------------------------
# USER REGISTER / LOGIN
# -------------------------
async def handle_user_register(ws, env):
    payload = env.get("payload", {})
    username = payload.get("username")
    salt_hex = payload.get("salt")
    pwd_hash_hex = payload.get("pwd_hash")
    pubkey = payload.get("pubkey")

    if not username or not salt_hex or not pwd_hash_hex or not pubkey:
        await send_error(ws, "UNKNOWN_TYPE", "Missing fields for USER_REGISTER")
        return

    if username in db["users"]:
        await send_error(ws, "NAME_IN_USE", f"Username '{username}' exists")
        return

    user_id = str(uuid.uuid4())
    db["users"][username] = {
        "user_id": user_id,
        "salt": salt_hex,
        "pwd_hash": pwd_hash_hex,
        "pubkey": pubkey,
    }
    save_db(db)

    resp = {
        "type": "REGISTER_OK",
        "from": "server",
        "to": env.get("from", "client"),
        "ts": now_ms(),
        "payload": {"user_id": user_id},
        "sig": ""
    }
    await sign_and_send(ws, resp)
    print(f"🆕 Registered user '{username}' ({user_id[:8]}…)")

async def handle_auth_hello(ws, env):
    username = env["payload"].get("username")
    if not username or username not in db["users"]:
        await send_error(ws, "USER_NOT_FOUND", "Unknown username")
        return
    nonce = os.urandom(32)
    pending_auth[ws] = {"username": username, "nonce": nonce}
    resp = {
        "type": "AUTH_CHALLENGE",
        "from": "server",
        "to": env.get("from", "client"),
        "ts": now_ms(),
        "payload": {"nonce_b64": base64url_encode(nonce)},
        "sig": ""
    }
    await sign_and_send(ws, resp)


async def handle_auth_response(ws, env):
    if ws not in pending_auth:
        await send_error(ws, "INVALID_SIG", "No pending challenge")
        return

    username = pending_auth[ws]["username"]
    nonce = pending_auth[ws]["nonce"]
    proof_hex = env["payload"].get("proof_hmac_hex")
    pubkey = env["payload"].get("pubkey")
    user_id_claim = env.get("from")

    user_record = db["users"][username]
    key = bytes.fromhex(user_record["pwd_hash"])
    expected = hmac.new(key, nonce, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(proof_hex, expected):
        await send_error(ws, "BAD_PASSWORD", "Invalid credentials")
        return

    # Verification passed
    user_id = user_record["user_id"]
    local_users[user_id] = {
        "ws": ws,
        "pubkey": pubkey or user_record["pubkey"],
        "username": username
    }
    user_locations[user_id] = "local"

    now = now_ms()

    # 1. Tell new users: existing user list
    for uid, info in list(local_users.items()):
        if uid == user_id:
            continue
        advertise_existing = {
            "type": "USER_ADVERTISE",
            "from": server_id,
            "to": user_id,
            "ts": now,
            "payload": {
                "user_id": uid,
                "server_id": server_id,
                "meta": {
                    "username": info.get("username"),
                    "pubkey": info.get("pubkey")
                }
            },
            "sig": ""
        }
        await sign_and_send(ws, advertise_existing)

    # 2. Tell all old users: New user is online
    advertise_new = {
        "type": "USER_ADVERTISE",
        "from": server_id,
        "to": "*",
        "ts": now,
        "payload": {
            "user_id": user_id,
            "server_id": server_id,
            "meta": {
                "username": username,
                "pubkey": user_record["pubkey"]
            }
        },
        "sig": ""
    }
    await broadcast(advertise_new)
    for sid, ws2 in servers.items():
        if sid == server_id:
            continue
        try:
            await sign_and_send(ws2, advertise_new)
        except Exception:
            pass

    # 3. Return AUTH_OK to the new user
    ok = {
        "type": "AUTH_OK",
        "from": "server",
        "to": user_id,
        "ts": now_ms(),
        "payload": {"user_id": user_id},
        "sig": ""
    }
    await sign_and_send(ws, ok)

    pending_auth.pop(ws, None)
    print(f"✅ '{username}' authenticated ({user_id[:8]}…)")


# -------------------------
# MESSAGE ROUTING
# -------------------------

async def handle_msg_direct(env):
    from_user = env["from"]
    to_user = env["to"]

    if user_locations.get(to_user) == "local":
        if env["type"] == "MSG_DIRECT":
            deliver = {
                "type": "USER_DELIVER",
                "from": server_id,
                "to": to_user,
                "ts": env["ts"],
                "payload": env["payload"],
                "sig": ""
            }
        else:
            # FILE_START / FILE_CHUNK / FILE_END 
            deliver = env

        await sign_and_send(local_users[to_user]["ws"], deliver)

    else:
        # get connected server id - dest
        dest = user_locations.get(to_user)
        if dest and dest in servers:
            if env["type"] == "MSG_DIRECT":
                forward = {
                    "type": "SERVER_DELIVER",
                    "from": server_id,
                    "to": dest,
                    "ts": env["ts"],
                    "payload": {
                        "user_id": to_user,
                        **env["payload"]
                        # "user_ts": env["ts"]
                    },
                    "sig": ""
                }
            else:
                forward = env

            await sign_and_send(servers[dest], forward)
        else:
            print(f"❌ USER_NOT_FOUND {to_user}")

# -------------------------
# ERROR
# -------------------------
async def send_error(ws, code, detail):
    msg = {
        "type": "ERROR",
        "from": "server",
        "to": "*",
        "ts": now_ms(),
        "payload": {"code": code, "detail": detail},
        "sig": ""
    }
    await sign_and_send(ws, msg)

# -------------------------
# SERVER HANDSHAKE / GOSSIP
# -------------------------

def to_json(envelope: dict) -> str:
    return json.dumps(envelope)

async def connect_to_other_server(host, port, _server_id):
    uri = f"ws://{host}:{port}"
    try:
        ws = await websockets.connect(uri)
        servers[_server_id] = ws # connect to the new server
        print(f"🔗 Connected to server {_server_id} at {uri}")
        
        await ws.send(to_json(await make_server_hello_link(_server_id)))
        print(f"✅ Send SERVER_HELLO_LINK to server id: {_server_id}.")

        if server_id:
            announce = await make_server_announce(_server_id, MY_HOST, MY_PORT, SERVER_PUB_B64U)
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
    
async def make_server_announce(to_id: str, host: str, port: int, pubkey_b64u: str) -> dict:
    return make_signed_envelope(
        "SERVER_ANNOUNCE", server_id, to_id,
        {"host": host, "port": port, "pubkey": pubkey_b64u},
        SERVER_PRIVKEY,
    )

async def make_server_hello_link(to_sid: str) -> dict:
    return {
        "type": "SERVER_HELLO_LINK",
        "from": server_id,
        "to": to_sid,
        "ts": int(time.time() * 1000),
        "payload": {
            "host": MY_HOST,
            "port": MY_PORT,
            "pubkey": SERVER_PUB_B64U,
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
    

async def handle_server_deliver(envelope):
    # Forward to the server where the recipient lives (or deliver locally)
    target_user = envelope["payload"]["user_id"]
    
    if target_user not in local_users:
        print(f"❌ User {target_user} does not connect to this server.")
        return
    else:
        payload = {
            "ciphertext": envelope["payload"]["ciphertext"],
            "sender": envelope["payload"]["sender"],
            "sender_pub": envelope["payload"]["sender_pub"],
            "content_sig": envelope["payload"]["content_sig"]
        }
        deliver = {
            "type": "USER_DELIVER",
            "from": server_id,
            "to": target_user,
            "ts": envelope["ts"],
            "payload": payload,
            "sig": ""
        }
        await sign_and_send(local_users[target_user]["ws"], deliver)

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
    
    await broadcast(envelope)

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
    envelope = make_signed_envelope("USER_REMOVE", _server_id, "*", payload, SERVER_PRIVKEY)
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
            
# -------------------------
# INTRODUCER CONNECTION
# -------------------------
            
async def make_server_hello_join() -> dict:
    tmp_id = str(uuid.uuid4())
    return {
        "type": "SERVER_HELLO_JOIN",
        "from": tmp_id,
        "to": f"{INTRODUCER_HOST}:{INTRODUCER_PORT}",
        "ts": now_ms(),
        "payload": {"host": MY_HOST, "port": MY_PORT, "pubkey": SERVER_PUB_B64U},
        "sig": ""
    }

async def join_network():
    try:
        hello = await make_server_hello_join()
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


# -------------------------
# CLIENT HANDLER
# -------------------------
async def handle_client(ws):
    try:
        async for raw in ws:
            env = json.loads(raw)
            mtype = env.get("type")
            if mtype == "USER_REGISTER":
                await handle_user_register(ws, env)
            elif mtype == "AUTH_HELLO":
                await handle_auth_hello(ws, env)
            elif mtype == "AUTH_RESPONSE":
                await handle_auth_response(ws, env)
            elif mtype == "MSG_DIRECT":
                await handle_msg_direct(env)
            elif mtype in ("FILE_START","FILE_CHUNK","FILE_END"):
                await handle_msg_direct(env)
            # server
            elif mtype == "SERVER_HELLO_LINK":
                sid = env["from"]
                payload = env["payload"]
                host, port = payload["host"], payload["port"]
                # server_addrs[sid] = (host, port)
                # server_pubkeys[sid] = payload["pubkey"]
                uri = f"ws://{host}:{port}"
                websocket = await websockets.connect(uri)
                servers[sid] = websocket
                print(f"🔗 Connected to server {sid} at {uri} via SERVER_HELLO_LINK")

            elif mtype == "SERVER_ANNOUNCE":
                await handle_server_announce(env)

            elif mtype == "USER_ADVERTISE":
                await handle_user_advertise(env)

            elif mtype == "USER_REMOVE":
                await handle_user_remove(env)

            elif mtype == "SERVER_DELIVER":
                await handle_server_deliver(env)
                
            else:
                print(f"ℹ️ Unhandled {mtype}")
    except Exception as e:
        print(f"❌ Client handler error: {e}")
    finally:
        # Clean up disconnected users
        drop_uid = None
        for uid, info in list(local_users.items()):
            if info["ws"] == ws:
                drop_uid = uid
        if drop_uid:
            local_users.pop(drop_uid, None)
            user_locations.pop(drop_uid, None)
            rm = {
                "type": "USER_REMOVE",
                "from": server_id,
                "to": "*",
                "ts": now_ms(),
                "payload": {"user_id": drop_uid, "server_id": server_id},
                "sig": ""
            }
            print(f"👋 User {drop_uid} discounected.")
            await broadcast(rm)

# -------------------------
# MAIN
# -------------------------
        
async def main():
    print(f"🚀 Starting WebSocket server on {MY_HOST}:{MY_PORT}")
    ws_server = await websockets.serve(handle_client, MY_HOST, MY_PORT)
    await join_network()


if __name__ == "__main__":
    load_server_keys("server_priv.pem")
    asyncio.run(main())