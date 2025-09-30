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

SERVER_HOST = "172.26.126.178"  # adjust to your server IP
SERVER_PORT = 9001

KEY_FILE = "user_priv.pem"        # Encrypted PEM using your password
USER_ID_FILE = "user_id.txt"
USERNAME_FILE = "user_name.txt"
SALT_FILE = "user_salt.txt"       # hex salt we keep locally to recompute pwd_hash

DOWNLOADS_DIR = "downloads"       # where received files are written

# RSA-OAEP chunk size safe for 4096-bit key (k=512, hLen=32) => max 446; choose 400 for margin
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

# =================
# SIGNUP
# =================
async def signup():
    username = input("Choose a username: ").strip()
    password = input("Choose a password: ").strip()

    user_id = str(uuid.uuid4())
    priv = generate_rsa4096()
    pub_b64u = public_key_b64u_from_private(priv)

    # Derive salt and password hash (server stores this)
    salt = new_salt(16)
    pwd_hex = pwd_hash_hex(salt, password)

    # Save username & user_id locally
    with open(USER_ID_FILE, "w") as f:
        f.write(user_id)
    with open(USERNAME_FILE, "w") as f:
        f.write(username)
    with open(SALT_FILE, "w") as f:
        f.write(salt.hex())

    # Save encrypted private key PEM with your password
    with open(KEY_FILE, "wb") as f:
        f.write(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
            )
        )

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
                # keep server-provided canonical id
                with open(USER_ID_FILE, "w") as f:
                    f.write(assigned)
                user_id = assigned
            print(f"🎉 Registered on server. Your user_id is {user_id}")
        else:
            print("❌ Registration failed:", msg)

# =================
# LOGIN + CHAT LOOP
# =================
async def login():
    if not (os.path.exists(KEY_FILE) and os.path.exists(USER_ID_FILE) and os.path.exists(USERNAME_FILE) and os.path.exists(SALT_FILE)):
        print("❌ Missing local files. Run signup first.")
        return

    username = open(USERNAME_FILE).read().strip()
    user_id = open(USER_ID_FILE).read().strip()
    salt_hex = open(SALT_FILE).read().strip()
    salt = bytes.fromhex(salt_hex)

    password = input(f"Password for {username}: ").strip()

    # Load encrypted PEM with password
    with open(KEY_FILE, "rb") as f:
        pem = f.read()
    priv = load_pem_private_key(pem, password=password.encode("utf-8"))
    pub_b64u = public_key_b64u_from_private(priv)

    # Prepare local maps
    known_users = {}  # name -> {"uuid":..., "pubkey":...}
    uuid_lookup = {}  # uuid -> name

    uri = f"ws://{SERVER_HOST}:{SERVER_PORT}"
    async with websockets.connect(uri) as ws:
        print(f"🔌 Connected to server at {uri}")

        # ---- AUTH PHASE ----
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

        # Compute proof = HMAC_SHA256(key=pwd_hash_hex_bytes, msg=nonce)
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

        # Server will respond with AUTH_OK + USER_ADVERTISE fanout for current users
        # (We handle those in receiver loop below.)

        # ------------- SENDER LOOP -------------
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
                            print(f"⚠️ Don’t know user {target_name}")
                            continue
                        target_id = known_users[target_name]["uuid"]
                        recip_pub_b64u = known_users[target_name]["pubkey"]
                        if not recip_pub_b64u:
                            print(f"⚠️ Don’t know pubkey for {target_id}")
                            continue
                        recip_pub = load_public_key_b64u(recip_pub_b64u)

                        ciphertext = rsa_oaep_encrypt(recip_pub, message)
                        ciphertext_b64u = b64u(ciphertext)

                        ts = now_ms()
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

                # List known users
                elif cmd == "/list":
                    print("Known users:", ", ".join(known_users.keys()) or "(none)")

                # File send: /file <username> <path>
                elif cmd.startswith("/file "):
                    try:
                        _, target_name, path = cmd.split(" ", 2)
                        if target_name not in known_users:
                            print(f"⚠️ Don’t know user {target_name}")
                            continue
                        target_id = known_users[target_name]["uuid"]
                        recip_pub_b64u = known_users[target_name]["pubkey"]
                        if not recip_pub_b64u:
                            print(f"⚠️ Don’t know pubkey for {target_id}")
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
        recv_files = {}  # file_id -> {"name": str, "size": int, "sha256": str, "chunks": dict, "received": int}

        # ------------- RECEIVER LOOP -------------
        async def receiver_loop():
            ensure_dirs()
            try:
                while True:
                    raw = await ws.recv()
                    env = json.loads(raw)
                    mtype = env.get("type")

                    if mtype == "AUTH_OK":
                        # optional: print success
                        pass

                    elif mtype == "USER_DELIVER":
                        payload = env["payload"]
                        # DM or file chunk (both carry ciphertext)
                        if "file_id" not in payload:
                            # Plain DM
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
                                    print(f"\n💬 DM from {sender_name}: {plaintext}")
                                else:
                                    print(f"\n⚠️ DM signature invalid from {sender_name}: {plaintext}")
                            except Exception as e:
                                print(f"\n❌ Failed to decrypt DM: {e}")
                        else:
                            # FILE_CHUNK delivered through USER_DELIVER path (we sent it as FILE_CHUNK originally)
                            # Some servers might relay FILE_* directly; our server wraps everything as USER_DELIVER,
                            # so handle both possibilities below in generic FILE_* branches too.
                            pass

                    elif mtype == "USER_ADVERTISE":
                        uid = env["payload"]["user_id"]
                        meta = env["payload"].get("meta", {})
                        uname = meta.get("username")
                        pubkey = meta.get("pubkey")
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

                    # File transfer primitives (server forwards these as-is in this build)
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
                            # Late start; initialize minimal (should not happen normally)
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
                        # Print anything unexpected to help debug
                        # print(f"📩 {env}")
                        pass

            except websockets.exceptions.ConnectionClosed as e:
                print(f"⚠️ Disconnected: {e}")
            except Exception as e:
                print(f"❌ Receiver error: {e}")

        await asyncio.gather(sender_loop(), receiver_loop())

# =========
# MAIN
# =========
if __name__ == "__main__":
    choice = input("signup or login? ").strip().lower()
    if choice == "signup":
        asyncio.run(signup())
    else:
        asyncio.run(login())