import asyncio
import websockets
import json
import time
import os
import hmac
import hashlib
import uuid

# =========================
# Simple persistent "DB"
#   users_db.json structure:
#   {
#     "users": {
#        "<username>": {
#           "user_id": "<uuidv4>",
#           "salt": "<hex>",
#           "pwd_hash": "<hex>",     # SHA256(salt || password)
#           "pubkey": "<b64url>"
#        }
#     }
#   }
# =========================

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

# In-memory presence & routing tables ( SOCP §5.2 )
local_users = {}         # user_id -> {"ws": websocket, "pubkey": str, "username": str}
user_locations = {}      # user_id -> "local"
pending_auth = {}        # websocket -> {"username": str, "nonce": bytes}

# Utility
def now_ms():
    return int(time.time() * 1000)

async def broadcast(msg):
    dead = []
    for uid, info in local_users.items():
        try:
            await info["ws"].send(json.dumps(msg))
        except Exception:
            dead.append(uid)
    for uid in dead:
        try:
            del local_users[uid]
        except KeyError:
            pass

# ================
# AUTHN FLOW
# ================
# Client messages:
#  - USER_REGISTER:   {username, password_hash?, pubkey} -> here we accept: username, salt, pwd_hash, pubkey
#  - AUTH_HELLO:      {username, user_id?} -> server replies AUTH_CHALLENGE {nonce}
#  - AUTH_RESPONSE:   {username, proof_hmac_hex, pubkey?}
# Server verifies proof = HMAC_SHA256(key=pwd_hash_hex_bytes, msg=nonce).
# On success -> mark websocket as this user, advertise presence, send existing users.

async def handle_user_register(websocket, env):
    payload = env.get("payload", {})
    username = str(payload.get("username", "")).strip()
    salt_hex = str(payload.get("salt", "")).strip()
    pwd_hash_hex = str(payload.get("pwd_hash", "")).strip()
    pubkey = payload.get("pubkey")

    if not username or not salt_hex or not pwd_hash_hex or not pubkey:
        await send_error(websocket, "UNKNOWN_TYPE", "Missing fields for USER_REGISTER")
        return

    users = db.setdefault("users", {})
    if username in users:
        await send_error(websocket, "NAME_IN_USE", f"Username '{username}' already exists")
        return

    # Assign a user_id (UUIDv4) and store
    user_id = str(uuid.uuid4())
    users[username] = {
        "user_id": user_id,
        "salt": salt_hex,
        "pwd_hash": pwd_hash_hex,
        "pubkey": pubkey
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
    await websocket.send(json.dumps(resp))
    print(f"🆕 Registered user '{username}' ({user_id[:8]}…)")

async def handle_auth_hello(websocket, env):
    payload = env.get("payload", {})
    username = str(payload.get("username", "")).strip()
    if not username or username not in db.get("users", {}):
        await send_error(websocket, "USER_NOT_FOUND", "Unknown username")
        return

    nonce = os.urandom(32)
    pending_auth[websocket] = {"username": username, "nonce": nonce}

    resp = {
        "type": "AUTH_CHALLENGE",
        "from": "server",
        "to": env.get("from", "client"),
        "ts": now_ms(),
        "payload": {"nonce_b64": base64url_encode(nonce)},
        "sig": ""
    }
    await websocket.send(json.dumps(resp))
    print(f"🔒 AUTH_CHALLENGE sent to '{username}'")

async def handle_auth_response(websocket, env):
    payload = env.get("payload", {})
    if websocket not in pending_auth:
        await send_error(websocket, "INVALID_SIG", "No pending challenge")
        return

    username = pending_auth[websocket]["username"]
    nonce = pending_auth[websocket]["nonce"]
    proof_hex = str(payload.get("proof_hmac_hex", "")).strip()
    pubkey = payload.get("pubkey")
    user_id_claim = env.get("from")

    user_record = db["users"].get(username)
    if not user_record:
        await send_error(websocket, "USER_NOT_FOUND", "Unknown username")
        return

    stored_pwd_hash_hex = user_record["pwd_hash"]  # hex string
    key = bytes.fromhex(stored_pwd_hash_hex)

    expected = hmac.new(key, nonce, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(proof_hex, expected):
        await send_error(websocket, "BAD_PASSWORD", "Invalid credentials")
        return

    # Success: bind websocket to this user_id (prefer server-side canonical ID)
    user_id = user_record["user_id"]
    # Accept client 'from' mismatch only if empty/unknown; otherwise enforce match
    if user_id_claim and user_id_claim != user_id:
        # soft warning; we can ignore and proceed with canonical user_id
        pass

    # Store presence
    local_users[user_id] = {"ws": websocket, "pubkey": pubkey or user_record["pubkey"], "username": username}
    user_locations[user_id] = "local"

    # Keep server-stored pubkey authoritative unless client supplied a new one (you may choose to update DB)
    if pubkey and pubkey != user_record["pubkey"]:
        user_record["pubkey"] = pubkey
        save_db(db)

    # Notify newcomer about existing users
    now = now_ms()
    for uid, info in list(local_users.items()):
        if uid == user_id:
            continue
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
        try:
            await websocket.send(json.dumps(advertise_existing))
        except Exception:
            pass

    # Broadcast presence to everyone (local broadcast to clients here)
    advertise_new = {
        "type": "USER_ADVERTISE",
        "from": "server",
        "to": "*",
        "ts": now,
        "payload": {"user_id": user_id, "username": username, "pubkey": user_record["pubkey"]},
        "sig": ""
    }
    await broadcast(advertise_new)

    # Tell the client they're authenticated
    ok = {
        "type": "AUTH_OK",
        "from": "server",
        "to": user_id,
        "ts": now_ms(),
        "payload": {"user_id": user_id},
        "sig": ""
    }
    try:
        await websocket.send(json.dumps(ok))
    except Exception:
        pass

    # Cleanup challenge
    pending_auth.pop(websocket, None)
    print(f"✅ '{username}' authenticated ({user_id[:8]}…)")

# ================
# ROUTING / DELIVERY
# ================
def wrap_user_deliver(env):
    """Wrap incoming user content for final delivery."""
    return {
        "type": "USER_DELIVER",
        "from": "server",
        "to": env["to"],
        "ts": env["ts"],
        "payload": env["payload"],
        "sig": ""
    }

async def route_user_frame(env):
    target = env["to"]
    mtype = env.get("type", "")

    if target in local_users:
        if mtype == "MSG_DIRECT":
            # DMs get wrapped as USER_DELIVER (transport envelope)
            deliver = {
                "type": "USER_DELIVER",
                "from": "server",
                "to": target,
                "ts": env["ts"],
                "payload": env["payload"],
                "sig": ""
            }
        else:
            # FILE_START / FILE_CHUNK / FILE_END should be forwarded unchanged
            # so the receiver sees their actual types and handles them.
            deliver = env

        try:
            await local_users[target]["ws"].send(json.dumps(deliver))
        except Exception as e:
            print(f"❌ Delivery failed to {target}: {e}")
    else:
        print(f"⚠️ USER_NOT_FOUND for {target}")
        # Optional: notify sender
        err = {
            "type": "ERROR",
            "from": "server",
            "to": env["from"],
            "ts": now_ms(),
            "payload": {"code": "USER_NOT_FOUND", "detail": f"{target} not registered"},
            "sig": ""
        }
        sender = env["from"]
        if sender in local_users:
            try:
                await local_users[sender]["ws"].send(json.dumps(err))
            except Exception:
                pass

async def send_error(websocket, code, detail):
    msg = {
        "type": "ERROR",
        "from": "server",
        "to": "*",
        "ts": now_ms(),
        "payload": {"code": code, "detail": detail},
        "sig": ""
    }
    try:
        await websocket.send(json.dumps(msg))
    except Exception:
        pass

# Base64url helpers (no padding)
def base64url_encode(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

async def handle_client(websocket):
    try:
        async for raw in websocket:
            env = json.loads(raw)
            mtype = env.get("type", "")
            # AUTH / REGISTER
            if mtype == "USER_REGISTER":
                await handle_user_register(websocket, env)
            elif mtype == "AUTH_HELLO":
                await handle_auth_hello(websocket, env)
            elif mtype == "AUTH_RESPONSE":
                await handle_auth_response(websocket, env)

            # User content (DM + Files)
            elif mtype in ("MSG_DIRECT", "FILE_START", "FILE_CHUNK", "FILE_END"):
                await route_user_frame(env)

            # Legacy (compat): some clients might still send USER_HELLO; reject and guide.
            elif mtype == "USER_HELLO":
                await send_error(websocket, "UNKNOWN_TYPE",
                                 "Use AUTH_HELLO / AUTH_RESPONSE instead of USER_HELLO in this build.")
            else:
                print(f"ℹ️ Unhandled msg type {mtype}")

    except Exception as e:
        print(f"❌ Client handler error: {e}")
    finally:
        # Remove presence for any user bound to this websocket
        drop_uid = None
        for uid, info in list(local_users.items()):
            if info["ws"] == websocket:
                drop_uid = uid
                break
        if drop_uid:
            try:
                del local_users[drop_uid]
                user_locations.pop(drop_uid, None)
            except KeyError:
                pass
            print(f"👋 User {drop_uid[:8]}… disconnected.")
            rm = {
                "type": "USER_REMOVE",
                "from": "server",
                "to": "*",
                "ts": now_ms(),
                "payload": {"user_id": drop_uid},
                "sig": ""
            }
            await broadcast(rm)

        pending_auth.pop(websocket, None)

async def main():
    async with websockets.serve(handle_client, "0.0.0.0", 9001):
        print("🌐 Server running on ws://0.0.0.0:9001")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
