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

SERVER_HOST = "10.13.114.172"  # adjust to your server IP
SERVER_PORT = 9002

KEY_FILE = "user_priv.pem"
USER_ID_FILE = "user_id.txt"


# --- Signup: first time user ---
USERNAME_FILE = "user_name.txt"
def signup():
    user_id = str(uuid.uuid4())
    priv = generate_rsa4096()
    pub_b64u = public_key_b64u_from_private(priv)

    username = input("Choose a username: ").strip()

    # Save private key
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
    with open(USERNAME_FILE, "w") as f:
        f.write(username)

    print(f"✅ Signed up as {username} ({user_id})")
    print(f"📂 Keys saved in {KEY_FILE}")


# --- Login + connect ---
async def login():
    if not os.path.exists(KEY_FILE) or not os.path.exists(USER_ID_FILE):
        print("❌ No user found, run signup first")
        return

    user_id = open(USER_ID_FILE).read().strip()
    username = open(USERNAME_FILE).read().strip()

    with open(KEY_FILE, "rb") as f:
        priv = load_private_key_pem(f.read())
    pub_b64u = public_key_b64u_from_private(priv)

    known_users = {}  # user_id -> pubkey (base64url)
    uuid_lookup = {}  # uuid -> username

    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    async with websockets.connect(uri) as ws:
        print(f"🔌 Connected to server at {uri}")

        # Send USER_HELLO
        hello_payload = {"client": "cli-v1", "username": username, "pubkey": pub_b64u, "enc_pubkey": pub_b64u}
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

        # --- sender loop ---
        async def sender_loop():
            while True:
                try:
                    cmd = await asyncio.to_thread(input, "> ")
                except EOFError:
                    await asyncio.sleep(0.25)
                    continue

                cmd = cmd.strip()
                if cmd.startswith("/tell "):
                    try:
                        _,target_name, *msg_parts = cmd.split(" ")
                        message = " ".join(msg_parts).encode("utf-8")
                        
                        if target_name not in known_users:
                            print(f"⚠️ Don’t know user {target_name}")
                            continue
                        target_id = known_users[target_name]["uuid"]
                        recip_pub_b64u = known_users[target_name]["pubkey"]
                        if not recip_pub_b64u:
                            print(f"⚠️ Don’t know pubkey for {target_id}")
                            continue
                        recip_pub = load_public_key_b64u(recip_pub_b64u)

                        ciphertext = rsa_oaep_encrypt(recip_pub, message)
                        ciphertext_b64u = base64.urlsafe_b64encode(ciphertext).decode().rstrip("=")

                        ts = int(time.time() * 1000)
                        content_sig = make_dm_content_sig(priv, ciphertext_b64u, user_id, target_id, ts)

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
                    print("Commands: /tell <user_name> <msg> | /list")

        # --- receiver loop ---
        async def receiver_loop():
            try:
                while True:
                    raw = await ws.recv()
                    env = json.loads(raw)
                    mtype = env.get("type")

                    if mtype == "USER_DELIVER":
                        payload = env["payload"]
                        try:
                            ciphertext = b64u_decode(payload["ciphertext"])
                            plaintext = rsa_oaep_decrypt(priv, ciphertext).decode("utf-8")

                            ok = verify_dm_content_sig(
                                sender_pub_b64u=payload["sender_pub"],
                                ciphertext_b64u=payload["ciphertext"],
                                sender_id=payload.get("sender", "?"),
                                recipient_id=env["to"],
                                ts=env["ts"],
                                content_sig_b64u=payload["content_sig"]
                            )

                            if ok:
                                sender_uuid = payload.get("sender")
                                sender_name = uuid_lookup.get(sender_uuid, sender_uuid[:8])  # fallback: uuid prefix
                                print(f"\n💬 DM from {sender_name}: {plaintext}")
                            else:
                                print(f"\n⚠️ DM received but signature invalid: {plaintext}")

                        except Exception as e:
                            print(f"\n❌ Failed to decrypt DM: {e}")

                    elif mtype == "USER_ADVERTISE":
                        uid = env["payload"]["user_id"]
                        uname = env["payload"].get("username")
                        pubkey = env["payload"].get("pubkey")
                        if uname and pubkey:
                            known_users[uname] = {"uuid": uid, "pubkey": pubkey}
                            uuid_lookup[uid] = uname
                            print(f"📡 Learned pubkey for {uname} ({uid[:8]}…)")
                    
                    elif mtype == "USER_REMOVE": #this is for other clients to get a message when a client is disconnected
                        uid = env["payload"]["user_id"]
                        uname = uuid_lookup.pop(uid, None)   # remove from reverse map
                        if uname:
                            known_users.pop(uname, None)
                            print(f"👋 {uname} disconnected")
                        else:
                            print(f"👋 User {uid[:8]}… disconnected")

                    else:
                        print(f"📩 {env}")

            except websockets.exceptions.ConnectionClosed as e:
                print(f"⚠️ Disconnected: {e}")
            except Exception as e:
                print(f"❌ Receiver error: {e}")

        await asyncio.gather(sender_loop(), receiver_loop())


# --- main entry ---
if __name__ == "__main__":
    choice = input("signup or login? ").strip().lower()
    if choice == "signup":
        signup()
    else:
        asyncio.run(login())
