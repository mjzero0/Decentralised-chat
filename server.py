import asyncio
import websockets
import json
import time



import hashlib
import os
import base64

# --- password hashing ---
def hash_password(password: str) -> str:
    # generate a 16-byte random salt
    salt = os.urandom(16)
    # PBKDF2 with SHA-256
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    # return base64(salt + key)
    return base64.b64encode(salt + key).decode("utf-8")

def verify_password(stored_hash: str, password: str) -> bool:
    data = base64.b64decode(stored_hash.encode("utf-8"))
    salt, key = data[:16], data[16:]
    # hash the given password with the same salt
    new_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return new_key == key




USERS_FILE = "users.json"

def load_users():
    import json, os
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    import json
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)




# Local user table: user_id -> {"ws": websocket, "pubkey": str}
local_users = {}

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
    payload = env["payload"]
    username = payload.get("username")
    password = payload.get("password")
    pubkey = payload.get("pubkey")
    user_id = env["from"]

    users = load_users()

    if username in users:
        if not verify_password(users[username]["password_hash"], password):
            print(f"❌ Login failed for {username} (bad password)")
            return
        print(f"✅ {username} logged in")
    else:
        print(f"🆕 Signup: {username}")
        users[username] = {
            "password_hash": hash_password(password),
            "uuid": user_id,
            "pubkey": pubkey
        }


    save_users(users)


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
