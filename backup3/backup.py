async def handle_client(websocket):
    try:
        async for raw in websocket:
            env = json.loads(raw)
            mtype = env.get("type")

            if mtype == "USER_HELLO":
                await handle_user_hello(websocket, env)
                
            elif mtype == "MSG_DIRECT":
                await handle_msg_direct(env)

            elif mtype == "USER_REMOVE":
                await handle_user_remove(env)

            elif mtype == "SERVER_ANNOUNCE":
                await handle_server_announce(env)
                
            elif mtype == "SEND_SERVER_INFO":
                await handle_send_server_info(env)
                
            elif mtype == "SEND_USER_INFO":
                await handle_send_user_info(env)
           
            else:
                print(f"ℹ️ Unhandled msg type {mtype}")

    except Exception as e:
        print(f"❌ Client handler error: {e}")
    finally:
        # Remove user if disconnected
        for uid, info in list(local_users.items()):
            if info["ws"] == websocket:
                del local_users[uid]
                print(f"👋 User {uid} disconnected.")
                # Broadcast removal
                rm = {
                    "type": "USER_REMOVE",
                    "from": "server",
                    "to": "*",
                    "ts": int(time.time() * 1000),
                    "payload": {"user_id": uid},
                    "sig": ""
                }
                await broadcast(rm)
                
    except Exception as e:
        print(f"⚠️ Connection closed or error: {e}")

        # Detect a user disconnect
        disconnected_user = None
        for uid, link in list(local_users.items()):
            if link == websocket:
                disconnected_user = uid
                break

        if disconnected_user:
            del local_users[disconnected_user]
            user_locations.pop(disconnected_user, None)
            await broadcast_user_remove(disconnected_user, server_id)
            print(f"👋 User {disconnected_user} disconnected and removed.")
                
async def main():
    async with websockets.serve(handle_client, "0.0.0.0", 9001):
        print("🌐 Server running on ws://0.0.0.0:9001")
        await asyncio.Future()  # run forever
        
        
        
async def handle_user_hello(websocket, env):
    user_id = env["from"]
    payload = env["payload"]
    pubkey = payload.get("pubkey")
    username = payload.get("username")

    local_users[user_id] = {"ws": websocket, "pubkey": pubkey, "username": username}
    print(f"👋 New user {username} ({user_id}) connected.")

    now = int(time.time() * 1000)

    # Tell newcomer about existing users
    for uid, info in list(local_users.items()):
        if uid == user_id: continue
        advertise_existing = {
            "type": "USER_ADVERTISE",
            "from": "server",
            "to": user_id,
            "ts": now,
            "payload": {
                "user_id": uid,
                "username": info.get("username"),
                "pubkey": info.get("pubkey")
            },
            "sig": ""
        }
        await websocket.send(json.dumps(advertise_existing))

    # Broadcast newcomer
    advertise_new = {
        "type": "USER_ADVERTISE",
        "from": "server",
        "to": "*",
        "ts": now,
        "payload": {"user_id": user_id, "username": username, "pubkey": pubkey},
        "sig": ""
    }

    await broadcast(advertise_new)
    
    # Simple duplicate guard
    if user_id in local_users or user_id in user_locations:
        error_msg = {"type": "ERROR", "code": "NAME_IN_USE", "reason": f"user_id '{user_id}' already exists"}
        await websocket.send(json.dumps(error_msg))
        print(f"❌ Duplicate user_id: {user_id}, rejected.")
        return

    local_users[user_id] = websocket
    user_locations[user_id] = "local"

    payload = {"user_id": user_id, "server_id": server_id, "meta": {}}
    env = make_signed_envelope("USER_ADVERTISE", server_id, "*", payload, server_priv)
    print(f"📣 New user {user_id} connected.")

    for ws in servers.values():
        await ws.send(json.dumps(env))
    print(f"📡 Broadcasting USER_ADVERTISE for {user_id}")
    
    # handle_server_deliver:
    payload = {
                "ciphertext": envelope["payload"]["ciphertext"],
                "sender": envelope["payload"]["sender"],
                "sender_pub": envelope["payload"]["sender_pub"],
                "content_sig": envelope["payload"]["content_sig"]
            }

# async def broadcast_user_remove(user_id: str, _server_id: str):
#     payload = {"user_id": user_id, "server_id": _server_id}
#     envelope = make_signed_envelope("USER_REMOVE", _server_id, "*", payload, SERVER_PRIVKEY)
#     print(f"📤 Broadcasting USER_REMOVE for {user_id}")

#     for sid, ws in servers.items():
#         try:
#             await ws.send(json.dumps(envelope))
#         except Exception as e:
#             print(f"❌ Failed to send USER_REMOVE to {sid}: {e}")