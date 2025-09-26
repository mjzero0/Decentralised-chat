import asyncio
import websockets
import json
import time

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
