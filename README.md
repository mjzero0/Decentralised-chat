# Decentralised Chat

A Python implementation of the **Secure Overlay Chat Protocol (SOCP) v1.3**.
The system supports secure end-to-end encrypted messaging between users across multiple servers, bootstrapped through an introducer.

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

### 1. Create a virtual environment

```bash
python -m venv venv
```

### 2. Activate a virtual environment

```bash
source venv/bin/activate     # macOS/Linux
venv\Scripts\activate        # Windows (PowerShell)
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

### `server.py`

* `INTRODUCER_HOST` in line 25: set to the **IP address of the device running the introducer**.
* `MY_HOST` in line 29: set to the **IP address of the current server device**.
* `MY_PORT` in line 30: set MY_PORT to any port you prefer. If left unchanged, it defaults to 9001.

### `client.py`

* `SERVER_HOST` in line 26: set to the **IP of the server you want to connect to** (can be your own machine or another server in the network).
* `SERVER_PORT` in line 27: set to the **PORT of the server you want to connect to** (can be your own machine or another server in the network).

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

### Start introducer

In one terminal:
```bash
python introducer.py
```

### Start server

Open another terminal:

```bash
python generate_keys.py
```

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
* Heartbeats (15s) and connection timeout (45s).
* Errors standardized (`USER_NOT_FOUND`, `INVALID_SIG`, etc.).

---

## Notes

* All servers must store known user public keys and server public keys for verification.
* Introducer must be started before any server can join the network.
* Each team’s submission must include at least 2 intentional **backdoors/vulnerabilities** (per assignment spec).
