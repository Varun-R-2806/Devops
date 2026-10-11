"""
main.py — Hybrid Post-Quantum Cryptography (PQC) Chat Service
FastAPI + WebSocket server deployable on Render (free tier) and any container host.

Features:
- Serves an interactive, responsive Web Dashboard & Live Chat UI at /
- Provides /ws/chat WebSocket endpoint for both Web and Python CLI clients
- Implements hybrid ECDH (P-256) + Kyber512 (ML-KEM-512) key exchange
- Enforces AES-256-GCM authenticated encryption for all chat traffic
- Includes /healthz health check for Render zero-downtime health probes
"""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import secrets
from typing import Dict, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import oqs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDH

from crypto_utils import (
    generate_ecdh_keypair,
    derive_hybrid_key,
    encrypt_message,
    decrypt_message,
    b64encode,
    b64decode,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("pqc_server")

# ---------------------------------------------------------------------------
# Connection State
# ---------------------------------------------------------------------------
@dataclass
class ClientSession:
    websocket: WebSocket
    session_id: str
    username: str
    client_type: str = "web"  # "web" or "cli"
    session_key: Optional[bytes] = None
    key_fingerprint: Optional[str] = None
    server_ecdh_priv: Optional[object] = None
    server_kem: Optional[oqs.KeyEncapsulation] = None
    handshake_complete: bool = False
    connected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    messages_sent: int = 0


class ConnectionManager:
    def __init__(self):
        self.active_sessions: Dict[WebSocket, ClientSession] = {}
        self.total_connections: int = 0
        self.total_messages: int = 0

    async def register(self, websocket: WebSocket, username: str, client_type: str) -> ClientSession:
        session_id = secrets.token_hex(4)
        session = ClientSession(
            websocket=websocket,
            session_id=session_id,
            username=username,
            client_type=client_type,
        )
        self.active_sessions[websocket] = session
        self.total_connections += 1
        logger.info(f"Registered session {session_id} for user '{username}' ({client_type})")
        return session

    def unregister(self, websocket: WebSocket):
        if websocket in self.active_sessions:
            session = self.active_sessions.pop(websocket)
            if session.server_kem:
                try:
                    session.server_kem.free()
                except Exception:
                    pass
            logger.info(f"Unregistered session {session.session_id} ('{session.username}')")

    async def broadcast_system(self, text: str):
        msg = {
            "type": "system",
            "text": text,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        dead = []
        for ws, session in self.active_sessions.items():
            try:
                await ws.send_text(json.dumps(msg))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.unregister(ws)

    def get_online_users(self):
        return [
            {
                "session_id": s.session_id,
                "username": s.username,
                "client_type": s.client_type,
                "secured": s.handshake_complete,
                "fingerprint": s.key_fingerprint,
                "connected_at": s.connected_at,
            }
            for s in self.active_sessions.values()
        ]


manager = ConnectionManager()


# ---------------------------------------------------------------------------
# FastAPI App Lifecycle & Routes
# ---------------------------------------------------------------------------
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)

app = FastAPI(
    title="Hybrid Post-Quantum Cryptography (PQC) Secured Chat",
    description="NIST PQC ML-KEM / Kyber512 + ECDH SECP256R1 hybrid key exchange over WebSockets",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
async def health_check():
    """Render health check endpoint for zero-downtime container monitoring."""
    return {
        "status": "healthy",
        "service": "hybrid-pqc-chat",
        "pqc_algorithm": "Kyber512 (ML-KEM-512)",
        "classical_algorithm": "ECDH (SECP256R1)",
        "cipher": "AES-256-GCM",
        "kdf": "HKDF-SHA256",
        "active_clients": len(manager.active_sessions),
        "total_connections": manager.total_connections,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/info")
async def get_pqc_info():
    """Technical architecture and cryptographic primitives specifications."""
    return {
        "name": "Hybrid Post-Quantum Cryptography Chat",
        "threat_model": {
            "classical_attacks": "Protected by ECDH (SECP256R1 / P-256)",
            "quantum_attacks": "Protected by Kyber512 (NIST FIPS 203 ML-KEM)",
            "transition_standard": "Meets NIST, ETSI, and BSI hybrid transition guidelines",
        },
        "handshake_steps": [
            "1. Server generates ephemeral ECDH (P-256) and Kyber512 keypairs and transmits public keys.",
            "2. Client generates ephemeral ECDH keypair, encapsulates Kyber512 public key, and sends back client ECDH pubkey + Kyber ciphertext.",
            "3. Both parties compute ECDH shared secret and Kyber shared secret.",
            "4. Both parties run HKDF-SHA256(ecdh_secret || kyber_secret) with domain tag 'hybrid-pqc-chat-v1' to yield a 256-bit AES-GCM session key.",
            "5. All messages are encrypted with AES-256-GCM with fresh 96-bit random nonces.",
        ],
        "active_clients_count": len(manager.active_sessions),
        "online_users": manager.get_online_users(),
    }


@app.post("/api/handshake/encapsulate")
async def encapsulate_for_web(body: dict):
    """
    Helper endpoint enabling web browser clients without native WASM/OQS
    to emulate the client-side Kyber encapsulation step during visual demos.
    """
    server_kyber_pub_b64 = body.get("server_kyber_pub")
    if not server_kyber_pub_b64:
        raise HTTPException(status_code=400, detail="Missing server_kyber_pub")

    try:
        pub_bytes = b64decode(server_kyber_pub_b64)
        client_kem = oqs.KeyEncapsulation("Kyber512")
        ct, ss = client_kem.encap_secret(pub_bytes)
        client_kem.free()
        return {
            "kyber_ciphertext": b64encode(ct),
            "kyber_shared_secret": b64encode(ss),
        }
    except Exception as e:
        logger.error(f"Encapsulation helper error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# WebSocket Endpoint: /ws/chat
# ---------------------------------------------------------------------------
@app.websocket("/ws/chat")
async def websocket_chat_endpoint(websocket: WebSocket):
    await websocket.accept()

    query_params = websocket.query_params
    requested_username = query_params.get("username") or f"Guest-{secrets.token_hex(2).upper()}"
    client_type = query_params.get("client_type") or "web"

    session = await manager.register(websocket, requested_username, client_type)

    try:
        # --- Step 1: Server generates ephemeral keypairs ---
        ecdh_priv, ecdh_pub_bytes = generate_ecdh_keypair()
        session.server_ecdh_priv = ecdh_priv

        kem = oqs.KeyEncapsulation("Kyber512")
        kyber_pub_bytes = kem.generate_keypair()
        session.server_kem = kem

        init_payload = {
            "type": "handshake_init",
            "session_id": session.session_id,
            "server_ecdh_pub": b64encode(ecdh_pub_bytes),
            "server_kyber_pub": b64encode(kyber_pub_bytes),
            "curve": "SECP256R1",
            "kem": "Kyber512",
            "ecdh_pub_len": len(ecdh_pub_bytes),
            "kyber_pub_len": len(kyber_pub_bytes),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await websocket.send_text(json.dumps(init_payload))

        # --- Step 2: Await client handshake reply ---
        reply_raw = await websocket.receive_text()
        reply_data = json.loads(reply_raw)

        if reply_data.get("type") != "handshake_reply":
            await websocket.send_text(json.dumps({"type": "error", "message": "Expected handshake_reply"}))
            return

        if reply_data.get("username"):
            session.username = reply_data["username"]

        client_ecdh_pub_bytes = b64decode(reply_data["client_ecdh_pub"])
        kyber_ciphertext = b64decode(reply_data["kyber_ciphertext"])

        # Compute ECDH shared secret
        client_ecdh_pub = serialization.load_der_public_key(client_ecdh_pub_bytes)
        ecdh_shared_secret = session.server_ecdh_priv.exchange(ECDH(), client_ecdh_pub)

        # Decapsulate Kyber ciphertext
        kyber_shared_secret = session.server_kem.decap_secret(kyber_ciphertext)

        # Derive 32-byte AES-256 session key
        session_key = derive_hybrid_key(ecdh_shared_secret, kyber_shared_secret)
        session.session_key = session_key
        session.key_fingerprint = session_key[:8].hex()
        session.handshake_complete = True

        # Free KEM resources
        session.server_kem.free()
        session.server_kem = None

        logger.info(
            f"Handshake SUCCESS with {session.username} ({session.client_type}). "
            f"Key Fingerprint: {session.key_fingerprint}"
        )

        # Confirm completion to client
        ack_payload = {
            "type": "handshake_complete",
            "session_id": session.session_id,
            "username": session.username,
            "status": "ready",
            "key_fingerprint": session.key_fingerprint,
            "session_key_hex_preview": session_key[:6].hex() + "...",
            "online_users": manager.get_online_users(),
        }
        await websocket.send_text(json.dumps(ack_payload))

        # Notify others
        await manager.broadcast_system(
            f"{session.username} ({session.client_type.upper()}) joined the PQC channel. "
            f"Key fingerprint: {session.key_fingerprint}"
        )

        # --- Continuous Encrypted Messaging Loop ---
        while True:
            data_raw = await websocket.receive_text()
            data = json.loads(data_raw)
            msg_type = data.get("type")

            if msg_type == "encrypted_msg":
                payload_b64 = data.get("payload")
                if not payload_b64:
                    continue

                encrypted_blob = b64decode(payload_b64)
                try:
                    plaintext = decrypt_message(session.session_key, encrypted_blob)
                except Exception as dec_err:
                    logger.warning(f"Decryption error for {session.username}: {dec_err}")
                    await websocket.send_text(
                        json.dumps({"type": "error", "message": "Failed to decrypt message (AEAD tag mismatch)"})
                    )
                    continue

                session.messages_sent += 1
                manager.total_messages += 1
                logger.info(f"[{session.username} -> Server] Decrypted: '{plaintext}'")

                # Broadcast to other online secured peers
                other_peers = [
                    (ws, s)
                    for ws, s in manager.active_sessions.items()
                    if ws != websocket and s.handshake_complete and s.session_key
                ]

                for peer_ws, peer_session in other_peers:
                    try:
                        # Re-encrypt with peer's specific post-quantum session key
                        peer_encrypted = encrypt_message(peer_session.session_key, plaintext)
                        peer_packet = {
                            "type": "chat_msg",
                            "sender": session.username,
                            "payload": b64encode(peer_encrypted),
                            "ciphertext_hex_preview": peer_encrypted.hex()[:32] + "...",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                        await peer_ws.send_text(json.dumps(peer_packet))
                    except Exception as broadcast_err:
                        logger.error(f"Broadcast error to {peer_session.username}: {broadcast_err}")

                # If sender is alone or wants assistant confirmation, generate Quantum Bot reply
                if not other_peers or session.client_type == "web":
                    bot_replies = [
                        f"Post-quantum handshake verified! Received '{plaintext}'. Zero tampering detected on AES-256-GCM tag.",
                        f"Encrypted message delivered across hybrid channel. Shor's algorithm cannot compromise Kyber512 secret.",
                        f"PQC channel active. Hybrid secret = ECDH(P-256) + Kyber512, derived via HKDF-SHA256.",
                    ]
                    reply_text = bot_replies[(manager.total_messages - 1) % len(bot_replies)]

                    bot_encrypted = encrypt_message(session.session_key, reply_text)
                    bot_packet = {
                        "type": "chat_msg",
                        "sender": "[Bot] Quantum AI",
                        "payload": b64encode(bot_encrypted),
                        "ciphertext_hex_preview": bot_encrypted.hex()[:32] + "...",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    # Slight delay for natural chat rhythm
                    await asyncio.sleep(0.3)
                    await websocket.send_text(json.dumps(bot_packet))

            elif msg_type == "ping":
                await websocket.send_text(json.dumps({"type": "pong", "online_count": len(manager.active_sessions)}))

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for {session.username}")
    except Exception as exc:
        logger.error(f"WebSocket exception in session {session.session_id}: {exc}")
    finally:
        departed_user = session.username
        manager.unregister(websocket)
        await manager.broadcast_system(f"{departed_user} left the channel.")


# Serve static web dashboard
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse(
        {
            "service": "Hybrid Post-Quantum Cryptography Chat",
            "message": "API is online. Web dashboard initializing.",
        }
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    logger.info(f"Starting PQC Server on port {port}...")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
