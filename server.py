import asyncio
import websockets
import json
import time
import hashlib
import os
import base64
import tempfile

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

def ensure_users_file():
    # Create empty {} file if missing or invalid
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            f.write("{}")
        return
    try:
        with open(USERS_FILE, "r") as f:
            _ = json.load(f)
    except Exception:
        with open(USERS_FILE, "w") as f:
            f.write("{}")

def load_users():
    ensure_users_file()
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def atomic_write_json(path: str, obj: dict):
    # Write to temp and replace atomically to avoid partial/corrupt writes
    dir_ = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix="users_", suffix=".json", dir=dir_)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise

def save_users(users):
    atomic_write_json(USERS_FILE, users)
    print(f"[AUTH] Saved users DB to: {USERS_FILE}")
    print(f"[AUTH] Current users DB:\n{json.dumps(users, indent=2)}")

# ----------------------------
# Runtime state
# ----------------------------
# user_id (uuid) -> {"ws": websocket, "pubkey": str, "username": str}
local_users = {}

async def broadcast(msg):
    dead = []
    for uid, info in list(local_users.items()):
        try:
            await info["ws"].send(json.dumps(msg))
        except Exception:
            dead.append(uid)
    for uid in dead:
        local_users.pop(uid, None)

async def send_and_close(websocket, code=1000, reason=""):
    try:
        await websocket.close(code=code, reason=reason)
    except Exception:
        pass

# ----------------------------
# Handlers
# ----------------------------
async def handle_user_hello(websocket, env):
    payload  = env.get("payload", {}) or {}
    username = payload.get("username")
    password = payload.get("password")
    pubkey   = payload.get("pubkey")
    mode     = payload.get("mode", "login")  # "signup" or "login"
    user_id  = env.get("from")

    print(f"[AUTH] USERS_FILE path: {USERS_FILE}")

    # Basic validation
    if not isinstance(username, str) or not username.strip():
        print("[AUTH] Missing or empty username")
        await send_and_close(websocket, reason="missing username")
        return
    if not isinstance(password, str):
        print("[AUTH] Missing password field")
        await send_and_close(websocket, reason="missing password")
        return
    if not isinstance(user_id, str) or not user_id.strip():
        print("[AUTH] Missing/invalid user_id in envelope")
        await send_and_close(websocket, reason="missing user_id")
        return

    users = load_users()
    print(f"[AUTH] User exists? {username in users} (mode={mode})")

    if username in users:
        # ---- LOGIN flow (strict) ----
        if mode != "login":
            print(f"❌ Signup refused: '{username}' already exists")
            await send_and_close(websocket, reason="username already exists")
            return

        stored_hash = users[username].get("password_hash", "")
        if not stored_hash or not verify_password(stored_hash, password):
            print(f"❌ Login failed for {username} (bad password)")
            await send_and_close(websocket, reason="bad password")
            return

        print(f"✅ {username} logged in")
        # Optionally update pubkey if provided
        if isinstance(pubkey, str) and pubkey:
            users[username]["pubkey"] = pubkey
            save_users(users)

    else:
        # ---- SIGNUP flow (strict) ----
        if mode != "signup":
            print(f"❌ Login refused: '{username}' not found")
            await send_and_close(websocket, reason="user not found")
            return

        users[username] = {
            "password_hash": hash_password(password),
            "pubkey": pubkey if isinstance(pubkey, str) else ""
        }
        save_users(users)
        print(f"🆕 Created new user '{username}'")

    # Register live connection
    local_users[user_id] = {"ws": websocket, "pubkey": pubkey or "", "username": username}
    print(f"👋 New user {username} ({user_id}) connected. Online={len(local_users)}")

    await websocket.send(json.dumps({
        "type": "LOGIN_OK",
        "from": "server",
        "to": user_id,
        "ts": int(time.time() * 1000),
        "payload": {"status": "success"},
        "sig": ""
    }))

    # Presence gossip to this user (who's already online here)
    now = int(time.time() * 1000)
    for uid, info in list(local_users.items()):
        if uid == user_id:
            continue
        await websocket.send(json.dumps({
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
        }))

    # Broadcast newcomer to others
    await broadcast({
        "type": "USER_ADVERTISE",
        "from": "server",
        "to": "*",
        "ts": now,
        "payload": {"user_id": user_id, "username": username, "pubkey": pubkey},
        "sig": ""
    })

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
    else:
        print(f"⚠️ MSG_DIRECT target {target} not connected locally")

async def handle_client(websocket):
    try:
        async for raw in websocket:
            try:
                env = json.loads(raw)
            except Exception:
                print("⚠️ Dropping non-JSON frame")
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
        # Clean up disconnected user and broadcast removal
        for uid, info in list(local_users.items()):
            if info["ws"] is websocket:
                local_users.pop(uid, None)
                print(f"👋 User {uid} disconnected.")
                await broadcast({
                    "type": "USER_REMOVE",
                    "from": "server",
                    "to": "*",
                    "ts": int(time.time() * 1000),
                    "payload": {"user_id": uid},
                    "sig": ""
                })

# ----------------------------
# Main
# ----------------------------
async def main():
    ensure_users_file()
    async with websockets.serve(handle_client, "0.0.0.0", 9001):
        print(f"🌐 Server running on ws://0.0.0.0:9001")
        print(f"🗄️  Users DB: {USERS_FILE}")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
