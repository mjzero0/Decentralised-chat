# mock_user_disconnect.py

import asyncio
import websockets
import json
import uuid
import time
import base64

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9001
USER_ID = str(uuid.uuid4())

FAKE_PUBKEY = base64.urlsafe_b64encode(b"fake_user_public_key").decode("utf-8").rstrip("=")

def make_user_hello(user_id):
    return {
        "type": "USER_HELLO",
        "from": user_id,
        "to": "server_1",  # update if needed
        "ts": int(time.time() * 1000),
        "payload": {
            "client": "cli-v1",
            "pubkey": FAKE_PUBKEY,
            "enc_pubkey": FAKE_PUBKEY
        },
        "sig": ""
    }

async def simulate_user_lifecycle():
    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    async with websockets.connect(uri) as websocket:
        print(f"🔌 Connected as {USER_ID}")
        hello = make_user_hello(USER_ID)
        await websocket.send(json.dumps(hello))
        print("📨 Sent USER_HELLO")

        # 保持连接几秒
        await asyncio.sleep(5)

        # 主动断开（会触发 server 检测）
        print("❌ Closing connection...")
        await websocket.close()

if __name__ == "__main__":
    asyncio.run(simulate_user_lifecycle())
