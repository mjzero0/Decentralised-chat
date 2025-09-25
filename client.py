import os
import json
import uuid
import getpass
import websockets
import asyncio
import time

from common import (
    generate_rsa4096,
    public_key_b64u_from_private,
    load_private_key_pem,
    make_signed_envelope,
    rsa_oaep_encrypt,
    make_dm_content_sig,
)
from cryptography.hazmat.primitives import serialization

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9001

KEY_FILE = "user_priv.pem"
USER_ID_FILE = "user_id.txt"

# --- Signup: first time user ---
def signup():
    user_id = str(uuid.uuid4())
    priv = generate_rsa4096()
    pub_b64u = public_key_b64u_from_private(priv)

    # Save private key locally
    with open(KEY_FILE, "wb") as f:
        f.write(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(USER_ID_FILE, "w") as f:
        f.write(user_id)

    print(f"✅ Signed up as {user_id}")
    print(f"📂 Keys saved in {KEY_FILE}")

    # TODO: send signup frame to server so it stores user in DB

# --- Login + connect ---
async def login():
    if not os.path.exists(KEY_FILE) or not os.path.exists(USER_ID_FILE):
        print("❌ No user found, run signup first")
        return

    user_id = open(USER_ID_FILE).read().strip()
    with open(KEY_FILE, "rb") as f:
        priv = load_private_key_pem(f.read())
    pub_b64u = public_key_b64u_from_private(priv)

    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    async with websockets.connect(uri) as ws:
        print(f"🔌 Connected to server at {uri}")

        # Send USER_HELLO
        hello_payload = {"client": "cli-v1", "pubkey": pub_b64u, "enc_pubkey": pub_b64u}
        hello = {
            "type": "USER_HELLO",
            "from": user_id,
            "to": "server",
            "ts": int(time.time() * 1000),
            "payload": hello_payload,
            "sig": ""  # USER_HELLO allowed unsigned
        }
        await ws.send(json.dumps(hello))
        print(f"📤 Sent USER_HELLO as {user_id}")

        # Listen loop
        while True:
            msg = await ws.recv()
            print(f"📩 {msg}")

# --- main entry ---
if __name__ == "__main__":
    choice = input("signup or login? ").strip().lower()
    if choice == "signup":
        signup()
    else:
        asyncio.run(login())
