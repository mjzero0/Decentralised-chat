import os
import json
import uuid
import websockets
import asyncio
import time
import base64

from common import (
    generate_rsa4096,
    public_key_b64u_from_private,
    load_private_key_pem,
    rsa_oaep_encrypt,
    make_dm_content_sig,
    rsa_oaep_decrypt,
    b64u_decode,
    verify_dm_content_sig,
    load_public_key_b64u
)
from cryptography.hazmat.primitives import serialization

SERVER_HOST = "10.13.104.41"
SERVER_PORT = 9001

KEY_FILE = "user_priv.pem"
USER_ID_FILE = "user_id.txt"
USERNAME_FILE = "user_name.txt"


def signup():
    username = input("Choose a username: ").strip()
    password = input("Choose a password: ").strip()

    if os.path.exists(USER_ID_FILE):
        user_id = open(USER_ID_FILE).read().strip()
    else:
        user_id = str(uuid.uuid4())
        with open(USER_ID_FILE, "w") as f:
            f.write(user_id)

    if not os.path.exists(KEY_FILE):
        priv = generate_rsa4096()
        with open(KEY_FILE, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
    else:
        with open(KEY_FILE, "rb") as f:
            priv = load_private_key_pem(f.read())

    pub_b64u = public_key_b64u_from_private(priv)
    with open(USERNAME_FILE, "w") as f:
        f.write(username)

    print(f"✅ Signed up as {username} ({user_id})")
    print(f"📂 Keys saved in {KEY_FILE}")


async def login_or_signup(mode="login"):
    if not os.path.exists(KEY_FILE) or not os.path.exists(USER_ID_FILE):
        print("❌ No user found, run signup first")
        return

    username = open(USERNAME_FILE).read().strip()
    password = input("Enter password: ").strip()
    user_id = open(USER_ID_FILE).read().strip()

    with open(KEY_FILE, "rb") as f:
        priv = load_private_key_pem(f.read())
    pub_b64u = public_key_b64u_from_private(priv)

    known_users = {}
    uuid_lookup = {}

    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    async with websockets.connect(uri) as ws:
        print(f"🔌 Connected to server at {uri}")

        hello_payload = {
            "mode": mode,  # "signup" or "login"
            "client": "cli-v1",
            "username": username,
            "password": password,
            "pubkey": pub_b64u,
            "enc_pubkey": pub_b64u
        }
        hello = {
            "type": "USER_HELLO",
            "from": user_id,
            "to": "server",
            "ts": int(time.time() * 1000),
            "payload": hello_payload,
            "sig": ""
        }
        await ws.send(json.dumps(hello))
        print(f"📤 Sent USER_HELLO as {user_id} ({mode})")

        try:
            test_recv = await asyncio.wait_for(ws.recv(), timeout=2)
            env = json.loads(test_recv)
            if env.get("type") == "LOGIN_OK":
                print("✅ Login/signup confirmed")
            else:
                print("❌ Unexpected response after login:", env)
                return
        except asyncio.TimeoutError:
            print("❌ No response from server. Possibly rejected.")
            return
        except websockets.exceptions.ConnectionClosed:
            print("❌ Server rejected login/signup or closed the connection.")
            return

        # --- sender loop ---
        async def sender_loop():
            while True:
                cmd = await asyncio.to_thread(input, "> ")
                cmd = cmd.strip()
                if cmd.startswith("/tell "):
                    try:
                        _, target_name, *msg_parts = cmd.split(" ")
                        message = " ".join(msg_parts).encode("utf-8")
                        if target_name not in known_users:
                            print(f"⚠️ Don’t know user {target_name}")
                            continue
                        target_id = known_users[target_name]["uuid"]
                        recip_pub_b64u = known_users[target_name]["pubkey"]
                        recip_pub = load_public_key_b64u(recip_pub_b64u)
                        ciphertext = rsa_oaep_encrypt(recip_pub, message)
                        ciphertext_b64u = base64.urlsafe_b64encode(ciphertext).decode().rstrip("=")
                        ts = int(time.time() * 1000)
                        content_sig = make_dm_content_sig(
                            priv, ciphertext_b64u, user_id, target_id, ts
                        )
                        payload = {
                            "ciphertext": ciphertext_b64u,
                            "sender": user_id,
                            "sender_pub": pub_b64u,
                            "content_sig": content_sig
                        }
                        env = {
                            "type": "MSG_DIRECT",
                            "from": user_id,
                            "to": target_id,
                            "ts": ts,
                            "payload": payload,
                            "sig": ""
                        }
                        await ws.send(json.dumps(env))
                        print(f"📤 Sent DM to {target_name}: {message.decode()}")
                    except Exception as e:
                        print(f"❌ Failed to send DM: {e}")
                elif cmd == "/list":
                    print("Known users:", ", ".join(known_users.keys()) or "(none)")
                else:
                    print("Commands: /tell <user> <msg> | /list")

        # --- receiver loop ---
        async def receiver_loop():
            try:
                while True:
                    raw = await ws.recv()
                    env = json.loads(raw)
                    mtype = env.get("type")
                    if mtype == "USER_ADVERTISE":
                        uid = env["payload"]["user_id"]
                        uname = env["payload"].get("username")
                        pubkey = env["payload"].get("pubkey")
                        if uname and pubkey:
                            known_users[uname] = {"uuid": uid, "pubkey": pubkey}
                            uuid_lookup[uid] = uname
                            print(f"📡 Learned pubkey for {uname} ({uid[:8]}…)")
                    elif mtype == "USER_REMOVE":
                        uid = env["payload"]["user_id"]
                        uname = uuid_lookup.pop(uid, None)
                        if uname:
                            known_users.pop(uname, None)
                            print(f"👋 {uname} disconnected")
                        else:
                            print(f"👋 User {uid[:8]}… disconnected")
                    else:
                        print(f"📩 {env}")
            except websockets.exceptions.ConnectionClosed as e:
                print(f"⚠️ Disconnected: {e}")

        await asyncio.gather(sender_loop(), receiver_loop())


if __name__ == "__main__":
    choice = input("signup or login? ").strip().lower()
    if choice == "signup":
        signup()
        asyncio.run(login_or_signup("signup"))  # <-- FIXED: real signup
    elif choice == "login":
        asyncio.run(login_or_signup("login"))
    else:
        print("❌ Invalid choice. Please type 'signup' or 'login'")
