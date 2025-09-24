# mock_user.py

import asyncio
import websockets
import json
import uuid
import time
import base64

# 👇 连接目标 Server（可改成 server_2）
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9001
USER_ID = str(uuid.uuid4())  # 随机用户 ID

# 👇 伪造一个 RSA 公钥（只要格式对就行）
FAKE_PUBKEY = base64.urlsafe_b64encode(b"fake_user_public_key").decode("utf-8").rstrip("=")

def make_user_hello(user_id):
    payload = {
        "client": "cli-v1",
        "pubkey": FAKE_PUBKEY,
        "enc_pubkey": FAKE_PUBKEY  # 你没分开加密用 key 所以可以一样
    }

    envelope = {
        "type": "USER_HELLO",
        "from": user_id,
        "to": f"server_1",  # or server_2
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": ""  # 签名先空着
    }

    return json.dumps(envelope)

async def simulate_user():
    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    async with websockets.connect(uri) as websocket:
        print(f"🔌 Connected to Server at {uri} as user {USER_ID}")
        
        # 发送 USER_HELLO
        msg = make_user_hello(USER_ID)
        await websocket.send(msg)
        print(f"📨 Sent USER_HELLO:\n{msg}")

        # Optionally wait to receive something
        try:
            while True:
                response = await websocket.recv()
                print(f"📩 Received message:\n{response}")
        except websockets.exceptions.ConnectionClosed:
            print("❌ Connection closed")

if __name__ == "__main__":
    asyncio.run(simulate_user())
