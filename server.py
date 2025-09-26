import asyncio
import websockets
import json
import time
import hashlib
import os
import base64

# ----------------------------
# Password hashing (PBKDF2)
# ----------------------------
def hash_password(password: str) -> str:
    salt = os.urandom(16)  # 16-byte salt
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt + key).decode("utf-8")  # store base64(salt||key)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        data = base64.b64decode(stored_hash.encode("utf-8"))
        salt, key = data[:16], data[16:]
        new_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        return new_key == key
    except Exception:
        return False

# ----------------------------
# JSON "database" (fixed path)
# ----------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(HERE, "users.json")

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# ----------------------------
# Runtime state
# ----------------------------
# user_id (uuid) -> {"ws": websocket, "pubkey": str, "username": str}
local_users = {}

async def broadcast(msg):
    dead = []
    for uid, info in local_users.items():
        try:
            await info["ws"].send(json.dumps(msg))
        except Exception:
            dead.append(uid)
    for uid in dead:
        local_users.pop(uid, None)

# ----------------------------
# Handlers
# ----------------------------
async def handle_user_hello(websocket, env):
    payload  = env.get("payload", {})
    username = payload.get("username")
    password = payload.get("password")
    pubkey   = payload.get("pubkey")
    user_id  = env.get("from")

    # Basic checks
    if not isinstance(username, str) or not username:
        print("[AUTH] Missing/invalid username")
        await websocket.close()
        return
    if not isinstance(password, str):
        print("[AUTH] Missing password field")
        await websocket.close()
        return
    if not isinstance(user_id, str) or not user_id:
        print("[AUTH] Missing/invalid user_id in envelope")
        await websocket.close()
        return

    users = load_users()
    print(f"[AUTH] DB file: {USERS_FILE}")
    print(f"[AUTH] User exists? {username in users}")

    # Existing user -> verify password
    if username in users:
        stored_hash = users[username].get("password_hash", "")
        ok = verify_password(stored_hash, password)
        print(f"[AUTH] verify_password -> {ok}")
        if not ok:
            err = {
                "type": "ERROR",
                "from": "server",
                "to": user_id,
                "ts": int(time.time() * 1000),
                "payload": {"reason": "Wrong password"},
                "sig": ""
            }
            try:
                await websocket.send(json.dumps(err))
            finally:
                print(f"❌ Login failed for {username} (bad password)")
                await websocket.close()
                return

        print(f"✅ {username} logged in")
        # Refresh pubkey/uuid
        if pubkey:
            users[username]["pubkey"] = pubkey
        users[username]["uuid"] = user_id

    # New signup (first login acts as signup)
    else:
        print(f"🆕 Signup: {username}")
        users[username] = {
            "password_hash": hash_password(password),
            "uuid": user_id,
            "pubkey": pubkey or ""
        }

    # Persist after success
    save_users(users)
    print(f"[AUTH] Saved DB entry for {username}")

    # Register connection
    local_users[user_id] = {"ws": websocket, "pubkey": pubkey or "", "username": username}
    print(f"👋 New user {username} ({user_id}) connected.")

    now = int(time.time() * 1000)

    # Tell newcomer about existing local users
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
        await websocket.send(json.dumps(advertise_existing))

    # Broadcast newcomer to everyone else
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
    target = env.get("to")
    if target in local_users:
        deliver = {
            "type": "USER_DELIVER",
            "from": "server",
            "to": target,
            "ts": env.get("ts"),
            "payload": env.get("payload"),
            "sig": ""
        }
        try:
            await local_users[target]["ws"].send(json.dumps(deliver))
            print(f"✅ USER_DELIVER sent to {target}")
        except Exception as e:
            print(f"❌ Failed to deliver to {target}: {e}")

async def handle_client(websocket):
    try:
        async for raw in websocket:
            try:
                env = json.loads(raw)
            except Exception:
                continue
            mtype = env.get("type")

            if mtype == "USER_HELLO":
                await handle_user_hello(websocket, env)
            elif mtype == "MSG_DIRECT":
                await handle_msg_direct(env)
            else:
                print(f"ℹ️ Unhandled msg type {mtype}")

    except Exception as e:
        print(f"❌ Client handler error: {e}")
    finally:
        # Remove user if disconnected & broadcast USER_REMOVE
        for uid, info in list(local_users.items()):
            if info["ws"] is websocket:
                local_users.pop(uid, None)
                print(f"👋 User {uid} disconnected.")
                rm = {
                    "type": "USER_REMOVE",
                    "from": "server",
                    "to": "*",
                    "ts": int(time.time() * 1000),
                    "payload": {"user_id": uid},
                    "sig": ""
                }
                await broadcast(rm)

# ----------------------------
# Main
# ----------------------------
async def main():
    async with websockets.serve(handle_client, "0.0.0.0", 9001):
        print("🌐 Server running on ws://0.0.0.0:9001")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
