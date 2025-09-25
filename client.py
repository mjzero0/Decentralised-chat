import os
import json
import uuid
import time
import asyncio
import websockets
from common import (
    generate_rsa4096,
    public_key_b64u_from_private,
    load_private_key_pem,
    make_signed_envelope,
    rsa_oaep_encrypt,
    make_dm_content_sig,
)
from cryptography.hazmat.primitives import serialization

pubkey_cache = {}  # Global pubkey cache

SERVER_HOST = "10.13.104.41"
SERVER_PORT = 9001
KEY_FILE = "user_priv.pem"
USER_ID_FILE = "user_id.txt"

# --- Signup: first time user ---
def signup():
    user_id = str(uuid.uuid4())
    priv = generate_rsa4096()
    pub_b64u = public_key_b64u_from_private(priv)

    with open(KEY_FILE, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(USER_ID_FILE, "w") as f:
        f.write(user_id)

    print(f"✅ Signed up as {user_id}")
    print(f"📂 Keys saved in {KEY_FILE}")

# --- Send DM Helper ---
async def send_dm(ws, priv, user_id, target_id, msg, pub_cache):
    if target_id not in pub_cache:
        # Ask for pubkey
        ask = {
            "type": "GET_PUBKEY",
            "from": user_id,
            "to": "server",
            "ts": int(time.time() * 1000),
            "payload": {"user_id": target_id},
            "sig": "",
        }
        await ws.send(json.dumps(ask))
        print(f"🔍 Requesting pubkey for {target_id}")

        # Wait for pubkey (listen() will cache it)
        for _ in range(10):  # wait up to 5 seconds
            await asyncio.sleep(0.5)
            if target_id in pub_cache:
                break
        else:
            print(f"❌ Timeout waiting for pubkey for {target_id}")
            return

    # Now send the message
    pubkey_b64u = pub_cache[target_id]
    ciphertext = rsa_oaep_encrypt(msg.encode(), pubkey_b64u)
    content_sig = make_dm_content_sig(priv, msg)

    payload = {
        "ciphertext": ciphertext,
        "sender_pub": public_key_b64u_from_private(priv),
        "content_sig": content_sig,
    }

    env = make_signed_envelope("MSG_DIRECT", user_id, target_id, payload, priv)
    await ws.send(json.dumps(env))
    print(f"📤 Sent DM to {target_id}")

async def chat_loop(ws, priv, user_id, pubkey_cache):
    while True:
        try:
            cmd = input("> ").strip()
            if cmd.lower() == "/exit":
                print("👋 Bye!")
                break
            elif cmd.startswith("/tell "):
                try:
                    parts = cmd.split(" ", 2)
                    target = parts[1]
                    message = parts[2]
                    await send_dm(ws, priv, user_id, target, message, pubkey_cache)
                except Exception:
                    print(f"❗ Usage: /tell <uuid> <message>")
            else:
                print("💡 Use /tell <uuid> <message> or /exit")
        except KeyboardInterrupt:
            break

# --- Listen for server messages ---
async def listen(ws):
    while True:
        msg = await ws.recv()
        try:
            env = json.loads(msg)
            mtype = env.get("type")
            if mtype == "USER_DELIVER":
                sender = env.get("from")
                ciphertext = env["payload"]["ciphertext"]
                print(f"\n💬 From {sender}: {ciphertext}")
            elif mtype == "PUBKEY":
                user_id = env["payload"]["user_id"]
                pubkey = env["payload"]["pubkey"]
                pubkey_cache[user_id] = pubkey
                print(f"🔑 Cached pubkey for {user_id}")
            elif mtype == "ERROR":
                print(f"❌ {env['payload'].get('detail', 'Unknown error')}")
            else:
                print(f"📩 {msg}")
        except Exception as e:
            print(f"⚠️ Error processing message: {e}\n📩 Raw: {msg}")

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

        # USER_HELLO
        hello_payload = {"client": "cli-v1", "pubkey": pub_b64u, "enc_pubkey": pub_b64u}
        hello = {
            "type": "USER_HELLO",
            "from": user_id,
            "to": "server",
            "ts": int(time.time() * 1000),
            "payload": hello_payload,
            "sig": ""
        }
        await ws.send(json.dumps(hello))
        print(f"📤 Sent USER_HELLO as {user_id}")

        await asyncio.gather(
            listen(ws),
            chat_loop(ws, priv, user_id, pubkey_cache)
        )

# --- main entry ---
if __name__ == "__main__":
    choice = input("signup or login? ").strip().lower()
    if choice == "signup":
        signup()
    else:
        asyncio.run(login())
