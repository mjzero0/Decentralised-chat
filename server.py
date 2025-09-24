import asyncio
import websockets
import uuid
import time
import json
import base64
import os

# -------------------------
# CONFIGURATION
# -------------------------

INTRODUCER_HOST = "127.0.0.1"
INTRODUCER_PORT = 8765
INTRODUCER_ADDR = f"{INTRODUCER_HOST}:{INTRODUCER_PORT}"

# Your own externally accessible address and WS port (modify as needed or overwrite with environment variables)
MY_HOST = os.getenv("MY_HOST", "127.0.0.1")
MY_PORT = int(os.getenv("MY_PORT", "9001"))

# ---------- In-memory tables ----------
servers = {}         # server_id -> link (all other servers)
server_addrs = {}    # server_id -> (host, port) (all other servers)
local_users = {}     # user_id -> link (users belong to this server)
user_locations = {}  # user_id -> "local" | server_id (all users)
# Each Server MUST keep a short-term seen_ids cache for server-delivered frames (by (ts,from,to,hash(payload))) 
# and drop duplicates.
seen_ids = set()     # {(ts, from, to, sha256(payload))}

# -------------------------
# FAKE RSA PUBLIC KEY (normally base64url of DER bytes)
# -------------------------
FAKE_PUBKEY = base64.urlsafe_b64encode(b"my_fake_rsa_pubkey_4096_bytes").decode().rstrip("=")

# -------------------------
# ENVELOPE CREATOR
# -------------------------

def make_server_hello_join(server_id: str, host: str, port: int) -> dict:
    return {
        "type": "SERVER_HELLO_JOIN",
        "from": server_id,
        "to": f"{host}:{port}",
        "ts": int(time.time() * 1000),
        "payload": {
            "host": host,
            "port": port,
            "pubkey": FAKE_PUBKEY
        },
        "sig": ""  # allowed to omit in SOCP v1.2
    }

def to_json(envelope: dict) -> str:
    return json.dumps(envelope) + "\n"

def handle_server_welcome(envelope: dict):
    payload = envelope["payload"]
    assigned_id = payload["assigned_id"]

    # Step 1: set server_id
    global server_id
    server_id = assigned_id
    print(f"✅ Assigned server_id: {server_id}")

    # Step 2: add introducer's pubkey/addr
    introducer_id = envelope["from"]
    print(f"📡 Introducer is {introducer_id}")

    # Step 3: update user_locations table（from introducer' clients）
    for client in payload.get("clients", []):
        user_id = client["user_id"]
        # TODO: CHECK IF THIS IS CORRECT
        user_locations[user_id] = (client["host"], client["port"])
        print(f"📥 Learned user {user_id} is on {(client["host"], client["port"])}")
        
def make_server_announce(from_id: str, host: str, port: int, pubkey_b64u: str) -> dict:
    return {
        "type": "SERVER_ANNOUNCE",
        "from": from_id,
        "to": "*", 
        "ts": int(time.time() * 1000),
        "payload": {
            "host": host,    
            "port": port,   
            "pubkey": pubkey_b64u 
        },
        "sig": "" # TODO
    }
    
async def connect_to_other_server(host, port, server_id):
    uri = f"ws://{host}:{port}"
    try:
        ws = await websockets.connect(uri)
        servers[server_id] = ws
        print(f"🔗 Connected to server {server_id} at {host}:{port}")
    except Exception as e:
        print(f"❌ Failed to connect to {server_id}: {e}")
        
async def handle_server_announce(envelope: dict):
    """Receive online broadcasts from other servers and register their addresses/public keys"""
    from_id = envelope.get("from")
    payload = envelope.get("payload", {})
    host = payload.get("host")
    port = payload.get("port")
    pubkey = payload.get("pubkey")

    if server_id and from_id == server_id:
        return

    # Basic verification (signature verification can be added if necessary)
    if not (from_id and host and port):
        print(f"⚠️ Malformed SERVER_ANNOUNCE: {envelope}")
        return

    # TODO: CHECK IF THIS IS CORRECT
    server_addrs[from_id] = (host, int(port), pubkey)

    print(f"🆕 Registered server {from_id} @ {host}:{port}")
    
    if from_id in servers:
        print(f"🔁 Already connected to {from_id}")
        return
    
    await connect_to_other_server(host, port, from_id)
                
async def handle_user_hello(user_id, link, server_id):
    # 1. 保存用户连接
    local_users[user_id] = link
    user_locations[user_id] = "local"

    # 2. 构造 USER_ADVERTISE frame
    payload = {
        "user_id": user_id,
        "server_id": server_id,
        "meta": {}  # 你可以以后加 display_name 等
    }

    envelope = {
        "type": "USER_ADVERTISE",
        "from": server_id,
        "to": "*",  # 广播给所有 Server
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": ""  # TODO: 签名
    }
    
    print(f"📣 New user {user_id} connected.")

    # 3. 广播给所有 Server
    for sid, ws in servers.items():
        await ws.send(json.dumps(envelope))
        
    print(f"📡 Broadcasting USER_ADVERTISE for {user_id}")
        
async def handle_user_advertise(envelope):
    payload = envelope["payload"]
    user_id = payload["user_id"]
    server_id = payload["server_id"]

    # 1. 验证签名（你可以先跳过）
    # TODO: verify envelope["sig"] with pubkey of envelope["from"]

    # 2. 更新 user_locations 表
    user_locations[user_id] = server_id
    
    print(f"🌍 USER_ADVERTISE received: {user_id} is at {server_id}")
    print(f"📌 user_locations[{user_id}] = {server_id}")


    # 3. 可选：转发给其他 Server（gossip）
    # 你也可以只转发一次，避免重复广播
    
async def handle_server_deliver(envelope):
    payload = envelope["payload"]
    user_id = payload["user_id"]
    to_server = user_locations.get(user_id)

    # 1. 如果用户是本地的，转成 USER_DELIVER 发给用户
    if to_server == "local":
        user_ws = local_users.get(user_id)
        if user_ws:
            user_envelope = {
                "type": "USER_DELIVER",
                "from": envelope["from"],
                "to": user_id,
                "ts": envelope["ts"],
                "payload": payload,
                "sig": ""  # 可选签名
            }
            await user_ws.send(json.dumps(user_envelope))
            print(f"📬 Delivered message to local user {user_id}")
        else:
            print(f"⚠️ User {user_id} not connected locally")

    # 2. 如果目标在另一个 server，转发过去
    elif isinstance(to_server, str) and to_server in servers:
        print(f"🔁 Forwarding to server {to_server}")
        await servers[to_server].send(json.dumps(envelope))

    # 3. 否则，用户位置未知，丢弃并 log
    else:
        print(f"❌ USER_NOT_FOUND: {user_id} (cannot route)")


async def broadcast_user_remove(user_id: str, server_id: str):
    payload = {
        "user_id": user_id,
        "server_id": server_id
    }

    envelope = {
        "type": "USER_REMOVE",
        "from": server_id,
        "to": "*",
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": ""  # TODO: 添加签名
    }

    print(f"📤 Broadcasting USER_REMOVE for {user_id}")

    for sid, ws in servers.items():
        try:
            await ws.send(json.dumps(envelope))
        except Exception as e:
            print(f"❌ Failed to send USER_REMOVE to {sid}: {e}")


async def handle_connection(websocket, path):
    try:
        raw = await websocket.recv()
        envelope = json.loads(raw)
        mtype = envelope.get("type")
        
        if mtype == "USER_HELLO":
            user_id = envelope["from"]
            await handle_user_hello(user_id, websocket, server_id)
        elif mtype == "USER_ADVERTISE":
            await handle_user_advertise(envelope)
        elif mtype == "SERVER_DELIVER":
            await handle_server_deliver(envelope)
        else:
            print(f"Unknown message type from client: {mtype}")
            
        while True:
            raw = await websocket.recv()
            envelope = json.loads(raw)
            mtype = envelope.get("type")

            if mtype == "USER_REMOVE":
                await handle_user_remove(envelope)
            else:
                print(f"📩 Message from user: {envelope}")

    except websockets.exceptions.ConnectionClosed:
        print("❌ User disconnected")

        # ❗找到哪个用户断开
        disconnected_user = None
        for uid, link in local_users.items():
            if link == websocket:
                disconnected_user = uid
                break

        if disconnected_user:
            del local_users[disconnected_user]
            await broadcast_user_remove(disconnected_user, server_id)
            
async def handle_user_remove(envelope):
    payload = envelope["payload"]
    user_id = payload["user_id"]
    target_server = payload["server_id"]

    # 避免误删
    if user_locations.get(user_id) == target_server:
        del user_locations[user_id]
        print(f"🗑️ Removed {user_id} from user_locations")
    else:
        print(f"⚠️ Skipped removal of {user_id}: mismatch server_id")

    # TODO: gossip 到其他 server，如果需要


async def join_network():
    temp_id = str(uuid.uuid4())
    hello = make_server_hello_join(temp_id, INTRODUCER_HOST, INTRODUCER_PORT)

    uri = f"ws://{INTRODUCER_HOST}:{INTRODUCER_PORT}"
    async with websockets.connect(uri) as websocket:
        print("🛰️ Connected to introducer")
        await websocket.send(to_json(hello))
        print("📤 Sent SERVER_HELLO_JOIN")

        # Continue reading messages: WELCOME → Send SERVER_ANNOUNCE; receive others' ANNOUNCE at the same time
        while True:
            raw = await websocket.recv()
            msg = json.loads(raw)
            mtype = msg.get("type")

            if mtype == "SERVER_WELCOME":
                handle_server_welcome(msg)

                # WELCOME and then immediately broadcast our online information (icon function)
                if server_id:
                    announce = make_server_announce(server_id, MY_HOST, MY_PORT, FAKE_PUBKEY)
                    await websocket.send(to_json(announce))
                    print(f"📣 Sent SERVER_ANNOUNCE for {server_id} ({MY_HOST}:{MY_PORT})")

            elif mtype == "SERVER_ANNOUNCE":
                await handle_server_announce(msg)

            else:
                # Other types of on-demand expansion (PING, ROUTE_UPDATE, etc.)
                print(f"ℹ️ Unhandled message type: {mtype}")
                
                
async def main():
    # 启动监听 WebSocket Server
    print(f"🚀 Starting WebSocket server on {MY_HOST}:{MY_PORT}")
    ws_server = await websockets.serve(handle_connection, MY_HOST, MY_PORT)

    # 同时运行 join_network()
    await join_network()

if __name__ == "__main__":
    asyncio.run(main())
