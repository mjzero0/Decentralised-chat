# Decentralised Chat

A Python implementation of the **Secure Overlay Chat Protocol (SOCP) v1.3**.
The system supports secure end-to-end encrypted messaging between users across multiple servers, bootstrapped through an introducer.

Developers: Group 43

- Mohammad Waezi: a1853470@adelaide.edu.au
- Zi Tao: a1916843@adelaide.edu.au
- Pahlavonjon Odilov: a1827303@adelaide.edu.au
- Mikaela Somers: a1852586@adelaide.edu.au

## For any inquiries please contact us.

---

## Features

* **Decentralised topology**: servers connect in an *n-to-n mesh*; each user attaches to one local server.
* **End-to-end encryption (E2EE)**: all direct messages, public channel messages, and file transfers use RSA-4096 + RSA-OAEP (SHA-256) encryption and RSASSA-PSS signatures.
* **Introducer bootstrap**: new servers announce themselves via a trusted introducer before linking with the rest of the network.
* **User presence gossip**: servers broadcast `USER_ADVERTISE` and `USER_REMOVE` for online/offline updates.
* **Public channel**: all users automatically join a shared broadcast channel.
* **Mandatory commands**:

  * `/list` → show online users
  * `/tell <user> <msg>` → direct message (E2EE)
  * `/all <msg>` → public channel broadcast
  * `/file <user> <path>` → encrypted file transfer

---


## Setup

### 1. Create a virtual environment and activate it (optional)

```bash
python -m venv venv
source venv/bin/activate     # macOS/Linux
venv\Scripts\activate        # Windows (PowerShell)
```

### 2. Install dependencies

```bash
pip install websockets==12.0
pip install cryptography>=42.0.0
```


## Configuration 

### In the `server.py`

* `INTRODUCER_HOST`  set to the **IP address of the device running the introducer**.
* `MY_HOST` set to the **IP address of the current server device**.
* `MY_PORT` set MY_PORT to any port you prefer. If left unchanged, it defaults to 9001.

### In the `client.py`

* `SERVER_HOST`  set to the **IP of the server you want to connect to** (can be your own machine or another server in the network).
* `SERVER_PORT`  set to the **PORT of the server you want to connect to** (can be your own machine or another server in the network).

---

## Finding Your IP Address

You will need your local machine’s IP to configure `MY_HOST` (server) or `SERVER_HOST` (client).

### macOS / Linux

```bash
ipconfig getifaddr en0
```
### Windows

```powershell
ipconfig
```

Look for **IPv4 Address** under your "Wireless LAN adapter Wi-Fi:", e.g. `192.168.1.20`.

---

## Running the system

### Generate keys for server

Open a terminal:

This needs to be run only once for the first time:
```bash
python generate_keys.py
```

### Start introducer

In one terminal:
```bash
python introducer.py
```

### Start the server

Open another terminal:

```bash
python server.py
```

### Start client

Open a third terminal:

```bash
python client.py
# enter username + password
```

You need to type 'sign up' for the first time, then it will ask you to create a username and a password. The program will be terminated after this step therefore you need to rerun the 'python client.py', then type 'log in' and use the credentials you created.

### More clients

Open another terminal and redo all steps above to have another user. You can then use the below commands to test their functionalities:

  * `/list` → show online users
  * `/tell <user> <msg>` → direct message (E2EE)
  * `/all <msg>` → public channel broadcast
  * `/file <user> <path>` → encrypted file transfer

---

## Protocol Compliance

This implementation follows the **SOCP v1.3 compliance checklist**:

* RSA-4096 keys for all encryption and signatures.
* JSON envelope format with mandatory `sig`.
* User/Server protocols for hello, advertise, gossip, DM, public channel, file transfer.
* Errors standardized (`USER_NOT_FOUND`, `INVALID_SIG`, etc.).

---

## Notes

* All servers must store known user public keys and server public keys for verification.
* Introducer must be started before any server can join the network.

---

## Test Plan & Current Status

| ID | Role | Action | Pass Criteria | Fail Criteria | Current Status |
|----|------|--------|---------------|---------------|----------------|
| 1  | New user | Sign up by typing 'signup' after running `python client.py` | The system will ask the user to enter an username and a password. | The system runs into error. | Pass |
| 2  | New user | Sign up with a duplicate username with other users. | The system will give a `NAME_IN_USE` error. | The user can sign up successfully. | Pass |
| 3  | User | Log in to the system by entering a correct password. | The user can successfully log in. | The system runs into error. | Pass |
| 4  | User | Log in to the system by entering a wrong password. | The system will give a warning about 'incorrect password'. | The user can successfully log in. | Pass |
| 5  | User | Typing `/list` command. | All the online users (no matter they are in the same server with the user or not) will be listed in the user's terminal. | The system runs into error or the user list is not complete. | Pass |
| 6  | User | Typing `/all {message}` command. | The system will show a message about 'the messsage has been sent and the message will be sent to all online users. | The system runs into error or the message has not been sent. | Pass |
| 7  | User | Receving `/all {message}` command from others. | All the online users (no matter they are in the same server with the sender or not) will receive this message. | The system runs into error or the message is not delivered. | Pass |
| 8  | User | Typing `/send {username} {message}` command. | The system will show a message about 'the messsage has been sent and the message will be sent to the specific user. | The system runs into error or the message has not been sent. | Pass |
| 9  | User | Receving `/send {username} {message}` command from others. | The user will receive the message from the sender. | The system runs into error or the message is not delivered. | Pass |
| 10  | User | Typing `/file {username} {file path}` command. | The system will show a message about 'the file has been transferred and the file will be sent to the specific user. | The system runs into error or the file has not been transferred. | Pass |
| 11  | User | Receving `/file {username} {file path}` command from others. | The user will receive the file from the sender, and the file will be in the `Download` folder. | The system runs into error or the file is not delivered. | Pass |

