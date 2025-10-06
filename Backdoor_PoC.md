# Backdoors / Vulnerabilities + Proof of Concepts
Four backdoors / vulnerabilites have been included in the backdoored submission.

## 1. Impersonation & Dual Logins

**Several users** can signup with the same username.
The code to check if a username already exists within the system has been removed, allowing several clients to signup with the same username. Both users are able to send and receive messages. The **first** user to signup will not know that another user is impersonating them, as the message indicating a new user has joined has been removed when there are duplicate usernames.

## 2. Secret Password login Override

## 3. Predictable Hashing Scheme

Using a **predictable** and **non random** salt for passwords.
The following part of `client.py` in the `signup()` function has been edited:

``` bash
    # Derive salt and password hash (server stores this)
    # salt = new_salt(16)
    username_bytes = username.encode("utf-8")
    # VULNERABILITY
    salt = username_bytes[:16].ljust(16,b'\x00')
    pwd_hex = pwd_hash_hex(salt, password)
```
Which generates a *fixed salt* with a users **username** and padded with **null bytes** to 16 bytes.
If an attacker knows the users username, the salt can be predicted, and a users password easily determined.

### Proof of Concept
* Assuming a user, Sarah, and an attacker.
* The attacker knows Sarah's username, which can be seen when the command `/list` is used.
* Through static analysis of the file client.py, the attacker can identify the logic used to generate password hashing, found in the `signup()` function.
* The attacker can see that the salt is not random, but is based on a users username.
* The attacker can then calcualte the predictable salt using Sarah's username:
   `b'Sarah'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 ` (hexadecimal)
* Now that the attacker knows the predictable hash formula and the target salt, they can test on several common passwords and look for matches.
* Once the attacker finds a match, they have determined Sarah's password.
* To log in on any client application, however, the attacker can modify the file client.py to ask for a users name, bypass the password prompt, and ask for the stolen key instead, such as inserting the following section of code into `client.py`:
```bash
# Attacker would enter Sarahs username here
if os.path.exists(USERNAME_FILE):
        with open(USERNAME_FILE, "r") as f:
            username = f.read().strip()
    else:
        username = input("username: ").strip()

 # Attacker then uses the correctly guessed key to log in as Sarah
 STOLEN_KEY = SHA256(b'Sarah'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 + guessed_password)
 key = bytes.fromhex(pwd_hex)
 proof = hmac.new(key, nonce, hashlib.sha256).hexdigest()
```
* The server accepts this as the stolen key matches the one in its database.
* This step allows the attacker to log in as Sarah from any client application.
* Since there is no minimum passsword length required, simple and predictable passwords may be chosen by users and hence be very easy for an attacker to guess using the above method.   
<br>


## 4. MITM Attack using Public Key Authentication

The network **does not properly authenticate public keys**. The `USER_ADVERTISE` message does not prove that the public key belongs to the claimed user. An attacker can force the sender of a message to encrypt using the attackers key, which can then be decrypted by the attacker and sent onwards to the reciever.
This can be seen in the following snippet of code from `server.py`:
```bash
 sender = envelope.get("from")
 if sender in server_pubkeys:
    if not verify_transport_sig(envelope, server_pubkeys[sender]):
        print(f"❌ Invalid signature on USER_ADVERTISE from {sender}")
        return
    
    # VULNERABILITY: NO CHECK FOR USER SIGNATURE.
    payload = envelope["payload"]
    user_id = payload["user_id"]
    src_server = payload["server_id"]

    # The server accepts and stores the key association blindly.
    user_locations[user_id] = src_server
    print(f"🌍 USER_ADVERTISE received: {user_id} is at {src_server}")
```

### Proof of Concept
* An attacker will tell the network that their public key belongs to **another user**, for example Sarah, which can then be used to encrypt Sarah's messages.
* The attacker must run a server of their own for the network to trust them.
* As a client, the attacker can view the usernames of Sarah and other clients on the `user_id.txt` file, and find their own public key after running the `generate_keys.txt` file and viewing the resultant key in `server_pub.pem`.
* The attacker can then create a spoofed envelope that tells a reciever to associate the attackers public key with Sarah, such as with the following JSON code, for example, which is injected into the attackers `server.py` file:

```bash
{
  "type": "USER_ADVERTISE",
  "from": "attacker-server-id",
  "to": "*",
  "ts": 1698774000000,
  "payload": {
    "user_id": "Sarah-uuid",
    "pubkey": "ATTACKERS_PUBLIC_KEY_B64U_STRING",
    "server_id": "mallory-server-id"
  },
  "sig": "VALID_SIGNATURE_BY_ATTACKER_PRIV"
```
* When another server recieves this, it checks to see that is it sent by a trusted server (the attackers server), and shares that the **attackers public key is now the key of Sarah**.
* The recieving servers do not check that this is **actually** the key belonging to Sarah, when in fact it is the attackers key.
* Now when a message is sent to Sarah from any other user, the messages are encrypted using the attacker's public key, and only the attacker's private key can decrypt this.
* The attacker can intercept the messages which are encrypted using their own key and decrypt them to plain text using the `rsa_oaep_decrypt` function.
* The plaintext message is then re-encrypted using the intended reciever's public key, and forward this to the intended reciever.
* This allows the attacker to **remain undetected** as the intended recipient still recieves their message, encrypted with their own key.
* In not checking that the public key belongs to the correct user, such an attack can occur.

<br>


## 5. Weak Key Acceptance & False Assurance

The system accepts **1024 bit** RSA keys, while claiming it enforces a **4096** key.
This change was made in the file `common.py`, where the following code has been changed to introduce an if statement to check the key size:

```bash
def load_public_key_b64u(b64u_der: str):
    der = b64u_decode(b64u_der)
    pub_key = serialization.load_der_public_key(der, backend=default_backend())
    key_size = pub_key.key_size
    
    # VULNERABILITY
    if key_size != 4096:
        if key_size == 1024:
            pass
        else:
            print(f"Key size {key_size} is prohibited, only accepting 4096-bit key.")
    return pub_key
```
This brings a false sense of security, since the system now accepts public **1024-bit** keys while claiming it only accepts strong 4096-bit keys. 
An attacker can inject and use a weak 1024 key.

### Proof of Concept
* An attacker that knows of this backdoor can modify their `generate_keys` file to create an **intentionally weak key**.
* The weak key is submitted during user/server registration, and is accepted and distributed to servers across the network.
* All messages sent to the attacker, such as messages or routing data, are encrypted using this weak key, but those sending the message believe they are using a secure 4096 key.
* Since the attacker is running their own server, they can modify the `server.py` file to log the incoming JSON message which includes the raw ciphertext, before the server attempts decryption.
* The attacker can then recover the corresponding private key, by factoring the weak public key using an algorithm such as **CADO-NFS**, which may take days.
* Using this private key, the malicious server can now decrypt the ciphertext, and the attacker can **read confidential, internal communications and data** of the network.   
<br>


## 5. Automatic Downloads and Directory Traversal Exploits

When a user sends another user a file, the file is received and **automatically** downloaded into a 'downloads' folder, without confirmation from the receiving user. There is no content filtering or verification to ensure the file is not malicious.
In addition to this, an attacker can potentially manipulate where the file will be saved on the receivers device.
There is no variable or function to determine if the user wants to accept the file or not, within the `client.py` file.

```bash
  elif mtype == "FILE_START":
        p = env["payload"]
        file_id = p["file_id"]
        recv_files[file_id] = {
            "name": p["name"],
            "size": int(p["size"]),
            "sha256": p["sha256"],
            "chunks": {},
            "received": 0,
            #VULNERABILITY: NO "accepted": false 
        }
        print(f"📥 FILE_START {p['name']} ({p['size']} bytes)")
```


### Proof of Concept
* As there is no way to accept or decline a file before it downloads onto the receiving user's device, an attacker can send **any file** to any user.
* The file has a size limit of 400-byte plaintext chunks, but there is no limit to how many files can be sent repeatedly to a user. An attacker may aim to **fill disk space**, or **send malware**, which will automatically be downloaded without an option to confirm or decline.
* The location that the file is saved to by default is a folder called 'downloads'. However, through the use of `/`, `\` and `../` within the file name itself, an attacker can **manipulate where the file will be saved**.
* The function `os.path.join()` within the file `client.py` which processes the file name does not sanitise `..` or `/` sequences. Hence, these characters will remain when the file name is processed by the outpath.
```bash
        outname = info["name"]
    outpath = os.path.join(DOWNLOADS_DIR, outname)
    Path(outpath).write_bytes(data)
    print(f"✅ Saved file to {outpath}")
    recv_files.pop(file_id, None)
```


* Using this, an attacker has the potential to create new folders within the intended downloads location, or using `../`, can **move up directory levels** out of the downloads folder, and save a file **anywhere** on the receiving user's system where the user has write permission.
ie `../../../startupp/malwaree.exe`
* This allows an attacker the potential to **place malicious files in dangerous locations**, such as within a users home folder, which could run attacker commands everytime a new terminal is opened, or within a system wide start up folder, which runs when a computer starts up.
