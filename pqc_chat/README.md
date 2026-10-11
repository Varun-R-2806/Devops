# Hybrid Post-Quantum Cryptography (PQC) Secured Chat

A complete, working demonstration and cloud-ready web application featuring a **hybrid key exchange** that combines classical elliptic-curve Diffie-Hellman (ECDH SECP256R1 / P-256) with the NIST post-quantum Key Encapsulation Mechanism (KEM) **Kyber512 (ML-KEM-512 / FIPS 203)**, producing a 256-bit AES-GCM session key for real-time encrypted messaging.

---

## Features

- **Dual-Mode Access**:
  - **Interactive Web App**: Responsive dark-mode dashboard with real-time 4-step handshake visualizer, cryptographic wire inspector (hex dumps of public keys, ciphertexts, and nonces), and live encrypted chat.
  - **Python Terminal CLI Client**: Connect from command-line terminals locally or over the internet via WebSockets.
- **Post-Quantum Cryptographic Suite**:
  - **Classical KEM**: ECDH SECP256R1 (P-256) NIST standard
  - **PQC KEM**: CRYSTALS-Kyber512 (ML-KEM-512 / NIST FIPS 203) via `liboqs`
  - **Key Derivation**: HKDF-SHA256 (`info=b"hybrid-pqc-chat-v1"`)
  - **AEAD Encryption**: AES-256-GCM with fresh 96-bit random nonces
- **Cloud-Ready for Free Hosting**:
  - Includes multi-stage `Dockerfile` and `render.yaml` Blueprint for **100% free hosting on Render** (or Koyeb, Hugging Face Spaces, Fly.io).
  - WebSockets over standard HTTPS (Port 443) bypasses restrictive cloud firewalls and operates seamlessly on all free cloud tiers.
  - Built-in `/healthz` zero-downtime health probe.

---

## Why Hybrid (Classical + PQC)?

| Threat Model | Classical ECDH Alone | Kyber512 Alone | Hybrid (Ours) |
|---|---|---|---|
| Today's adversaries | ✅ Secure | ✅ Secure | ✅ Secure |
| Future quantum computer (Shor's algorithm) | ❌ Broken | ✅ Secure | ✅ Secure |
| Undiscovered mathematical flaw in Kyber | ✅ Secure | ❌ Broken | ✅ Secure |

A hybrid scheme is secure **as long as at least one** of the two primitives remains unbroken. This is the official transition strategy recommended by NIST, ETSI, and the German BSI.

---

## Quickstart (Local Development)

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note**: `liboqs-python` requires the native `liboqs` shared library. On Linux/Docker, the included `Dockerfile` builds this automatically. On Windows, ensure pre-built `liboqs` or wheels are accessible.

### 2. Start the Full-Stack Web & WebSocket Server

```bash
python main.py
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser to view the interactive PQC dashboard and chat!

### 3. Connect from the Terminal (Python CLI)

Open another terminal:
```bash
# Interactive chat
python ws_client.py --username Alice

# Automated test / demo verification
python ws_client.py --demo
```

### 4. Original Raw TCP Socket Scripts (Optional)

You can also run the original standalone socket demonstration:
```bash
# Terminal 1
python server.py

# Terminal 2
python client.py
```

---

## Deploy to Free Cloud Hosting (Render)

### Option A: 1-Click Render Blueprint (Recommended)

1. Push your repository to GitHub (`https://github.com/Varun-R-2806/Devops`).
2. Go to [Render Dashboard](https://dashboard.render.com).
3. Click **New +** → **Blueprint**.
4. Select your **Devops** repository. Render automatically detects `render.yaml`.
5. Click **Apply**. Render builds the Docker image and provisions your free public URL (`https://<your-service>.onrender.com`).

### Option B: Manual Web Service on Render

1. In Render Dashboard, click **New +** → **Web Service**.
2. Select your GitHub repository.
3. Configure the following:
   - **Name**: `pqc-secure-chat`
   - **Runtime**: `Docker`
   - **Root Directory**: `pqc_chat` (or leave blank if deploying root)
   - **Plan**: `Free`
   - **Health Check Path**: `/healthz`
4. Click **Create Web Service**.

Once deployed, you can access the Web UI from anywhere and run the CLI client against your live deployment:
```bash
python ws_client.py --server wss://<your-app>.onrender.com/ws/chat --username Bob
```

---

## Protocol & Wire Architecture

```
CLIENT                                                           SERVER
  |                                                                |
  |  1. WebSocket Connect (/ws/chat)                               |
  |<--------------------- handshake_init --------------------------|
  |                       - server_ecdh_pub (91 B DER)             |
  |                       - server_kyber_pub (800 B)               |
  |                                                                |
  |  2. Client generates ECDH keypair                              |
  |     Client computes ecdh_shared_secret                         |
  |     Client encapsulates Kyber server pubkey                    |
  |       → (kyber_ciphertext, kyber_shared_secret)                |
  |                                                                |
  |---------------------- handshake_reply ------------------------>|
  |                       - client_ecdh_pub (91 B DER)             |
  |                       - kyber_ciphertext (768 B)               |
  |                                                                |
  |  3. Server computes ecdh_shared_secret                         |
  |     Server decapsulates kyber_ciphertext                       |
  |       → recovers kyber_shared_secret                           |
  |                                                                |
  |  4. Both parties execute HKDF:                                 |
  |     session_key = HKDF(ecdh_secret || kyber_secret)            |
  |                                                                |
  |<------------------- handshake_complete ------------------------|
  |                                                                |
  |  5. Authenticated AES-256-GCM Messaging                       |
  |---- {"type": "encrypted_msg", "payload": "<nonce || ct>"} ---->|
  |<--- {"type": "chat_msg", "payload": "<nonce || ct>"} ----------|
```

---

## Repository Structure

```
Devops/
├── render.yaml               # 1-Click Render Blueprint configuration
└── pqc_chat/
    ├── main.py               # FastAPI server + WebSocket PQC handler + Health check
    ├── ws_client.py          # Interactive & demo WebSocket Python CLI client
    ├── crypto_utils.py       # ECDH, Kyber, HKDF-SHA256, AES-256-GCM primitives
    ├── requirements.txt      # Python dependencies
    ├── Dockerfile            # Multi-stage container build with native liboqs
    ├── .dockerignore         # Exclusions for clean container builds
    ├── render.yaml           # Subdirectory Render config
    ├── server.py             # Original local TCP server
    ├── client.py             # Original local TCP client
    └── static/
        ├── index.html        # Modern PQC web dashboard
        ├── style.css         # Glassmorphism dark-mode styles
        └── app.js            # Web Crypto hybrid handshake & messaging
```
