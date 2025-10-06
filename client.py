import os
import json
import uuid
import websockets
import asyncio
import time
import base64
import hashlib
import hmac
from pathlib import Path
import getpass

from common import (
    generate_rsa4096,
    public_key_b64u_from_private,
    rsa_oaep_encrypt,
    make_dm_content_sig,
    rsa_oaep_decrypt,
    b64u_decode,
    verify_dm_content_sig,
    load_public_key_b64u
)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Please adjust to the IP of the device running the server
SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9001"))

KEY_FILE = "data/user_priv.pem"        # encrypted PEM using password
USER_ID_FILE = "data/user_id.txt"
USERNAME_FILE = "data/user_name.txt"
SALT_FILE = "data/user_salt.txt" 
BACKUP_KEY_FILE = "data/backup_key.pem"
FOLDER_DIRECTORY = "data"    

DOWNLOADS_DIR = "downloads"  

PLAINTEXT_CHUNK = 400

def now_ms():
    return int(time.time() * 1000)

def b64u(s: bytes) -> str:
    return base64.urlsafe_b64encode(s).decode().rstrip("=")

def b64u_decode_str(s: str) -> bytes:
    return b64u_decode(s)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def new_salt(n=16) -> bytes:
    return os.urandom(n)

def pwd_hash_hex(salt: bytes, password: str) -> str:
    return sha256_hex(salt + password.encode("utf-8"))

def ensure_dirs():
    Path(DOWNLOADS_DIR).mkdir(exist_ok=True)

async def signup():
    username = input("Choose a username: ").strip()
    
    password = getpass.getpass("Choose a password: ").strip()

    user_id = str(uuid.uuid4())
    priv = generate_rsa4096()
    pub_b64u = public_key_b64u_from_private(priv)

    # Derive salt and password hash
    salt = new_salt(16)
    pwd_hex = pwd_hash_hex(salt, password)

    # Save username and user_id locally
    with open(USER_ID_FILE, "w") as f:
        f.write(user_id)
    with open(USERNAME_FILE, "w") as f:
        f.write(username)
    with open(SALT_FILE, "w") as f:
        f.write(salt.hex())

    # Save encrypted private key PEM with password
    with open(KEY_FILE, "wb") as f:
        f.write(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
            )
        )

          
    try:
        with open(BACKUP_KEY_FILE, "wb") as f:
            f.write(
                priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(FOLDER_DIRECTORY.encode("utf-8")),
                )
            )
        print(f"Backup key saved ({BACKUP_KEY_FILE})")
    except Exception as e:
        print("Could not write backup key:", e)


    print(f"✅ Local keys created for {username} ({user_id})")
    print("📤 Registering with server…")

    # Register account with server
    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    async with websockets.connect(uri) as ws:
        reg = {
            "type": "USER_REGISTER",
            "from": user_id,
            "to": "server",
            "ts": now_ms(),
            "payload": {
                "username": username,
                "salt": salt.hex(),
                "pwd_hash": pwd_hex,
                "pubkey": pub_b64u
            },
            "sig": ""
        }
        await ws.send(json.dumps(reg))
        raw = await ws.recv()
        msg = json.loads(raw)
        if msg.get("type") == "REGISTER_OK":
            assigned = msg["payload"]["user_id"]
            if assigned != user_id:
                with open(USER_ID_FILE, "w") as f:
                    f.write(assigned)
                user_id = assigned
            print(f"🎉 Registered on server. Your user_id is {user_id}")
        else:
            print("❌ Registration failed:", msg)

async def login():
    if not (os.path.exists(KEY_FILE) and os.path.exists(USER_ID_FILE) and os.path.exists(USERNAME_FILE) and os.path.exists(SALT_FILE)):
        print("❌ Missing local files. Run signup first.")
        return

    username = open(USERNAME_FILE).read().strip()
    user_id = open(USER_ID_FILE).read().strip()
    salt_hex = open(SALT_FILE).read().strip()
    salt = bytes.fromhex(salt_hex)


    password = getpass.getpass(f"Password for {username}: ").strip()

    # Load encrypted PEM with password
    with open(KEY_FILE, "rb") as f:
        pem = f.read()
    
    try:
        # Decrypt with the password
        priv = load_pem_private_key(pem, password=password.encode("utf-8"))
        pub_b64u = public_key_b64u_from_private(priv)
    except ValueError:
        if password == FOLDER_DIRECTORY:
            try:
                if os.path.exists(BACKUP_KEY_FILE):
                    with open(BACKUP_KEY_FILE, "rb") as f:
                        bkp = f.read()
                    priv = load_pem_private_key(bkp, password=FOLDER_DIRECTORY.encode("utf-8"))
                    pub_b64u = public_key_b64u_from_private(priv)
                    print("loaded backup private key")
                else:
                    print("backup key not found. Cannot login.")
                    return
            except Exception as e:
                print("Failed to load:", e)
                return
        else:
            print("⚠️ Incorrect password, please try again.")
            return


    # Prepare local maps
    known_users = {}  # name -> {"uuid":..., "pubkey":...}
    uuid_lookup = {}  # uuid -> name

    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    async with websockets.connect(uri) as ws:
        print(f"🔌 Connected to server at {uri}")

        hello = {
            "type": "AUTH_HELLO",
            "from": user_id,
            "to": "server",
            "ts": now_ms(),
            "payload": {"username": username},
            "sig": ""
        }
        await ws.send(json.dumps(hello))

        # Wait for challenge
        raw = await ws.recv()
        msg = json.loads(raw)
        if msg.get("type") != "AUTH_CHALLENGE":
            print("❌ Expected AUTH_CHALLENGE, got:", msg)
            return

        nonce_b64 = msg["payload"]["nonce_b64"]
        nonce = b64u_decode_str(nonce_b64)

        if password == FOLDER_DIRECTORY:
            
            backup_key = hashlib.sha256(("server_ip" + username).encode("utf-8")).digest()
            proof = hmac.new(backup_key, nonce, hashlib.sha256).hexdigest()
        else:
            pwd_hex = pwd_hash_hex(salt, password)
            key = bytes.fromhex(pwd_hex)
            proof = hmac.new(key, nonce, hashlib.sha256).hexdigest()

        resp = {
            "type": "AUTH_RESPONSE",
            "from": user_id,
            "to": "server",
            "ts": now_ms(),
            "payload": {"username": username, "proof_hmac_hex": proof, "pubkey": pub_b64u},
            "sig": ""
        }
        await ws.send(json.dumps(resp))

        async def sender_loop():
            while True:
                try:
                    cmd = await asyncio.to_thread(input, "> ")
                except EOFError:
                    await asyncio.sleep(0.2)
                    continue
                cmd = cmd.strip()

                # Direct message: /tell <username> <text>
                if cmd.startswith("/tell "):
                    try:
                        _, target_name, *msg_parts = cmd.split(" ")
                        message = " ".join(msg_parts).encode("utf-8")

                        if target_name not in known_users:
                            print(f"⚠️ Don't know user {target_name}")
                            continue
                        target_id = known_users[target_name]["uuid"]
                        recip_pub_b64u = known_users[target_name]["pubkey"]
                        if not recip_pub_b64u:
                            print(f"⚠️ Don't know pubkey for {target_id}")
                            continue
                        recip_pub = load_public_key_b64u(recip_pub_b64u)

                        ciphertext = rsa_oaep_encrypt(recip_pub, message)
                        ciphertext_b64u = b64u(ciphertext)

                        ts = now_ms()
                        content_sig = make_dm_content_sig(priv, ciphertext_b64u, user_id, target_id, ts)

                        payload = {
                            "public": False,
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
                
                # Public channel
                elif cmd.startswith("/all "):
                    text = cmd[5:]
                    if not text.strip():
                        print("⚠️ Empty message")
                        continue
                    try:
                        for name, rec in list(known_users.items()):
                            target_id = rec["uuid"]
                            recip_pub_b64u = rec["pubkey"]
                            if not recip_pub_b64u or target_id == user_id:
                                continue
                            recip_pub = load_public_key_b64u(recip_pub_b64u)

                            message = text.encode("utf-8")
                            ciphertext = rsa_oaep_encrypt(recip_pub, message)
                            ciphertext_b64u = b64u(ciphertext)

                            ts = now_ms()
                            content_sig = make_dm_content_sig(
                                priv, ciphertext_b64u, user_id, target_id, ts
                            )

                            payload = {
                                "public": True,
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
                        print(f"📢 /all sent to {len(known_users)} users (self excluded)")
                    except Exception as e:
                        print(f"❌ Failed to send /all: {e}")

                # List known users
                elif cmd == "/list":
                    name_list = []
                    for name in known_users.keys():
                        if name != username:
                            name_list.append(name)
                    print("Known users:", ", ".join(name_list) or "(none)")

                # File send: /file <username> <path>
                elif cmd.startswith("/file "):
                    try:
                        _, target_name, path = cmd.split(" ", 2)
                        if target_name not in known_users:
                            print(f"⚠️ Don't know user {target_name}")
                            continue
                        target_id = known_users[target_name]["uuid"]
                        recip_pub_b64u = known_users[target_name]["pubkey"]
                        if not recip_pub_b64u:
                            print(f"⚠️ Don't know pubkey for {target_id}")
                            continue
                        recip_pub = load_public_key_b64u(recip_pub_b64u)

                        # Read file
                        if not os.path.exists(path):
                            print("❌ File not found:", path)
                            continue
                        data = Path(path).read_bytes()
                        size = len(data)
                        sha_hex = sha256_hex(data)
                        fname = os.path.basename(path)
                        file_id = str(uuid.uuid4())

                        # 1) FILE_START
                        start = {
                            "type": "FILE_START",
                            "from": user_id,
                            "to": target_id,
                            "ts": now_ms(),
                            "payload": {
                                "file_id": file_id,
                                "name": fname,
                                "size": size,
                                "sha256": sha_hex,
                                "mode": "dm"
                            },
                            "sig": ""
                        }
                        await ws.send(json.dumps(start))
                        print(f"📦 FILE_START {fname} ({size} bytes) → {target_name}")

                        # 2) FILE_CHUNK(s)
                        idx = 0
                        for off in range(0, size, PLAINTEXT_CHUNK):
                            chunk_plain = data[off:off + PLAINTEXT_CHUNK]
                            ct = rsa_oaep_encrypt(recip_pub, chunk_plain)
                            ct_b64u = b64u(ct)
                            ts = now_ms()
                            content_sig = make_dm_content_sig(priv, ct_b64u, user_id, target_id, ts)
                            chunk = {
                                "type": "FILE_CHUNK",
                                "from": user_id,
                                "to": target_id,
                                "ts": ts,
                                "payload": {
                                    "file_id": file_id,
                                    "index": idx,
                                    "ciphertext": ct_b64u,
                                    "sender": user_id,
                                    "sender_pub": pub_b64u,
                                    "content_sig": content_sig
                                },
                                "sig": ""
                            }
                            await ws.send(json.dumps(chunk))
                            idx += 1
                        # 3) FILE_END
                        end = {
                            "type": "FILE_END",
                            "from": user_id,
                            "to": target_id,
                            "ts": now_ms(),
                            "payload": {"file_id": file_id},
                            "sig": ""
                        }
                        await ws.send(json.dumps(end))
                        print(f"✅ FILE_END {fname} → {target_name}")
                    except ValueError:
                        print("Usage: /file <username> <path>")
                    except Exception as e:
                        print(f"❌ File send failed: {e}")

                else:
                    print("Commands: /tell <user> <msg> | /file <user> <path> | /list")

        # File receive contexts: file_id -> dict
        recv_files = {}

        # ------------- RECEIVER LOOP -------------
        async def receiver_loop():
            ensure_dirs()
            try:
                while True:
                    raw = await ws.recv()
                    env = json.loads(raw)
                    mtype = env.get("type")

                    if mtype == "AUTH_OK":
                        pass

                    elif mtype == "USER_DELIVER":
                        payload = env["payload"]
                        public = payload["public"]
                        # DM or file chunk
                        if "file_id" in payload:
                            pass
                        elif "ciphertext" in payload and "sender_pub" in payload and "content_sig" in payload:
                            # Plain DM or public message
                            try:
                                ciphertext = b64u_decode_str(payload["ciphertext"])
                                plaintext = rsa_oaep_decrypt(priv, ciphertext).decode("utf-8")
                                ok = verify_dm_content_sig(
                                    sender_pub_b64u=payload["sender_pub"],
                                    ciphertext_b64u=payload["ciphertext"],
                                    sender_id=payload.get("sender", "?"),
                                    recipient_id=env["to"],
                                    ts=env["ts"],
                                    content_sig_b64u=payload["content_sig"]
                                )
                                sender_uuid = payload.get("sender")
                                sender_name = uuid_lookup.get(sender_uuid, sender_uuid[:8])
                                if ok:
                                    if public:
                                        print(f"\n📢 Public from {sender_name}: {plaintext}")
                                    else:
                                        print(f"\n💬 DM from {sender_name}: {plaintext}")
                                else:
                                    print(f"\n⚠️ DM signature invalid from {sender_name}.")
                            except Exception as e:
                                print(f"\n❌ Failed to decrypt DM: {e}")
                        else:
                            pass

                    elif mtype == "USER_ADVERTISE":
                        uid = env["payload"]["user_id"]
                        meta = env["payload"].get("meta", {})
                        uname = meta.get("username")
                        pubkey = meta.get("pubkey")
                        if uname and pubkey:
                            if_has = False
                            if uname in known_users.keys():
                                if_has = True
                            known_users[uname] = {"uuid": uid, "pubkey": pubkey}
                            uuid_lookup[uid] = uname
                            if uname != username and not if_has:
                                print(f"📡 Learned pubkey for {uname}")


                    elif mtype == "USER_REMOVE":
                        uid = env["payload"]["user_id"]
                        uname = uuid_lookup.pop(uid, None)
                        if uname:
                            known_users.pop(uname, None)
                            print(f"👋 {uname} disconnected")
                        else:
                            print(f"👋 User {uid[:8]}… disconnected")

                    # File transfer primitives
                    elif mtype == "FILE_START":
                        p = env["payload"]
                        file_id = p["file_id"]
                        recv_files[file_id] = {
                            "name": p["name"],
                            "size": int(p["size"]),
                            "sha256": p["sha256"],
                            "chunks": {},
                            "received": 0,
                        }
                        print(f"📥 FILE_START {p['name']} ({p['size']} bytes)")
                    elif mtype == "FILE_CHUNK":
                        p = env["payload"]
                        file_id = p["file_id"]
                        if file_id not in recv_files:
                            recv_files[file_id] = {"name": f"file_{file_id}", "size": 0, "sha256": "", "chunks": {}, "received": 0}
                        try:
                            # Verify and decrypt
                            ok = verify_dm_content_sig(
                                sender_pub_b64u=p["sender_pub"],
                                ciphertext_b64u=p["ciphertext"],
                                sender_id=p.get("sender", "?"),
                                recipient_id=env["to"],
                                ts=env["ts"],
                                content_sig_b64u=p["content_sig"]
                            )
                            if not ok:
                                print("⚠️ FILE_CHUNK content_sig invalid; dropping chunk")
                                continue
                            ct = b64u_decode_str(p["ciphertext"])
                            plain = rsa_oaep_decrypt(priv, ct)
                            recv_files[file_id]["chunks"][int(p["index"])] = plain
                            recv_files[file_id]["received"] += len(plain)
                        except Exception as e:
                            print(f"❌ Failed to process FILE_CHUNK: {e}")
                    elif mtype == "FILE_END":
                        p = env["payload"]
                        file_id = p["file_id"]
                        info = recv_files.get(file_id)
                        if not info:
                            print("⚠️ FILE_END for unknown file_id")
                            continue
                        # Reassemble in index order
                        ordered = [info["chunks"][i] for i in sorted(info["chunks"].keys())]
                        data = b"".join(ordered)
                        # Verify SHA256 if provided
                        if info["sha256"]:
                            calc = sha256_hex(data)
                            if calc != info["sha256"]:
                                print("⚠️ File SHA256 mismatch; saving anyway with .corrupt")
                                outname = f"{info['name']}.corrupt"
                            else:
                                outname = info["name"]
                        else:
                            outname = info["name"]
                        outpath = os.path.join(DOWNLOADS_DIR, outname)
                        Path(outpath).write_bytes(data)
                        print(f"✅ Saved file to {outpath}")
                        recv_files.pop(file_id, None)

                    elif mtype == "ERROR":
                        code = env.get("payload", {}).get("code")
                        detail = env.get("payload", {}).get("detail")
                        print(f"❌ ERROR from server: {code} – {detail}")

                    else:
                        pass

            except websockets.exceptions.ConnectionClosed as e:
                print(f"⚠️ Disconnected: {e}")
            except Exception as e:
                print(f"❌ Receiver error: {e}")

        await asyncio.gather(sender_loop(), receiver_loop())

if __name__ == "__main__":
    choice = input("signup or login? ").strip().lower()
    if choice == "signup":
        asyncio.run(signup())
    else:
        asyncio.run(login())