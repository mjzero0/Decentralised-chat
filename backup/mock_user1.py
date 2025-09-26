# mock_user.py

import asyncio
import websockets
import json
import uuid
import time
import base64

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
        "to": "server_1",
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": ""  # 签名先空着
    }

    return json.dumps(envelope)

def make_envelope(user_id, receiver_id):
    envelope = {
        "type": "MSG_DIRECT",
        "from": user_id,
        "to": receiver_id,
        "ts": 1700000000000,
        "payload": {
            "ciphertext": "direct message test",
            "sender_pub": FAKE_PUBKEY,
            "content_sig": ""
        },
        "sig": ""
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
        
        msg2 = make_envelope(USER_ID, "908b909c-af9b-4b9a-a06b-202eff94348d")
        await websocket.send(msg2)
        print(f"📨 Sent direct message:\n{msg2}")

        # Optionally wait to receive something
        try:
            while True:
                response = await websocket.recv()
                print(f"📩 Received message:\n{response}")
        except Exception as e:
            print(f"❌ Failed: {e}")

if __name__ == "__main__":
    asyncio.run(simulate_user())
