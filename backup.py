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