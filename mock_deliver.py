# mock_server_deliver.py

import asyncio
import websockets
import json
import time
import base64
import uuid

# 配置：目标 Server 的地址（你要发消息给它）
TARGET_SERVER_HOST = "127.0.0.1"
TARGET_SERVER_PORT = 9001  # 请换成你实际监听的 server 端口
RECIPIENT_USER_ID = "ac99f28d-7d99-4be4-9ed6-5f23697b6b1e"  # 必须真实存在于目标 Server 的 local_users

# 模拟 sender server ID 和签名（不做真正加密）
SENDER_SERVER_ID = "mock_sender_server_1234"
SENDER_NAME = "mock_alice"

# 伪造公钥和签名
FAKE_RSA_PUB = base64.urlsafe_b64encode(b"fake_pubkey").decode().rstrip("=")
FAKE_SIG = base64.urlsafe_b64encode(b"fake_sig").decode().rstrip("=")
FAKE_CIPHERTEXT = base64.urlsafe_b64encode(b"secret_message").decode().rstrip("=")

def make_server_deliver():
    payload = {
        "user_id": RECIPIENT_USER_ID,
        "ciphertext": FAKE_CIPHERTEXT,
        "sender": SENDER_NAME,
        "sender_pub": FAKE_RSA_PUB,
        "content_sig": FAKE_SIG
    }

    envelope = {
        "type": "SERVER_DELIVER",
        "from": SENDER_SERVER_ID,
        "to": "target_server_id",  # 可选，SOCP 忽略这个字段
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": ""  # 可以留空
    }

    return envelope

async def main():
    uri = f"ws://{TARGET_SERVER_HOST}:{TARGET_SERVER_PORT}"
    async with websockets.connect(uri) as ws:
        print(f"🔗 Connected to target server at {uri}")
        envelope = make_server_deliver()
        await ws.send(json.dumps(envelope))
        print(f"📤 Sent SERVER_DELIVER to {TARGET_SERVER_HOST}:{TARGET_SERVER_PORT}")
        print(json.dumps(envelope, indent=2))

        # 等待回应（可选）
        try:
            response = await asyncio.wait_for(ws.recv(), timeout=3)
            print(f"📩 Received response:\n{response}")
        except asyncio.TimeoutError:
            print("⌛ No response (which is okay for fire-and-forget delivery)")

if __name__ == "__main__":
    asyncio.run(main())
