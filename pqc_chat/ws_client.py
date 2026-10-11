"""
ws_client.py — Post-Quantum Secured WebSocket Client
Connects to the PQC server (locally or on cloud platforms like Render),
performs a hybrid ECDH (P-256) + Kyber512 key encapsulation exchange,
derives an AES-256-GCM session key, and enables real-time encrypted chat.

Usage:
  Local test:
    python ws_client.py

  Interactive against Render cloud deployment:
    python ws_client.py --server wss://<your-app>.onrender.com/ws/chat --username Alice

  Automated single-message demo:
    python ws_client.py --demo
"""

import argparse
import asyncio
import json
import os
import sys
import secrets

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import oqs  # liboqs-python
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

# ANSI terminal colors for readable cryptographic logging
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"
RED = "\033[31m"


class PQCWebSocketClient:
    def __init__(self, uri: str, username: str):
        self.uri = uri
        self.username = username
        self.session_key: bytes | None = None
        self.kem: oqs.KeyEncapsulation | None = None
        self.ws = None
        self.running = True

    async def connect_and_handshake(self) -> bool:
        import websockets

        print(f"\n{BOLD}{CYAN}=== Hybrid Post-Quantum Cryptography (PQC) Client ==={RESET}")
        print(f"{BLUE}[CONNECTING]{RESET} Target: {self.uri}")
        print(f"{BLUE}[IDENTITY]{RESET} User: {self.username}\n")

        try:
            self.ws = await websockets.connect(self.uri)
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Failed to connect to {self.uri}: {e}")
            return False

        # --- Phase 1: Await Handshake Init from Server ---
        raw_init = await self.ws.recv()
        init_data = json.loads(raw_init)
        if init_data.get("type") != "handshake_init":
            print(f"{RED}[ERROR]{RESET} Unexpected initial packet: {init_data}")
            return False

        server_ecdh_pub_bytes = b64decode(init_data["server_ecdh_pub"])
        server_kyber_pub_bytes = b64decode(init_data["server_kyber_pub"])

        print(f"{MAGENTA}[STEP 1/4]{RESET} Received Server Ephemeral Public Keys:")
        print(f"  - Classical ECDH (SECP256R1): {len(server_ecdh_pub_bytes)} bytes")
        print(f"  - Post-Quantum Kyber512 (ML-KEM): {len(server_kyber_pub_bytes)} bytes")

        # --- Phase 2: Compute Client Keys & Encapsulation ---
        print(f"{MAGENTA}[STEP 2/4]{RESET} Performing Hybrid Key Agreement:")
        # 1. Ephemeral ECDH keypair
        client_ecdh_priv, client_ecdh_pub_bytes = generate_ecdh_keypair()
        server_ecdh_pub = serialization.load_der_public_key(server_ecdh_pub_bytes)
        ecdh_shared_secret = client_ecdh_priv.exchange(ECDH(), server_ecdh_pub)
        print(f"  - ECDH shared secret derived: {len(ecdh_shared_secret)} bytes")

        # 2. Kyber512 Encapsulation
        self.kem = oqs.KeyEncapsulation("Kyber512")
        kyber_ciphertext, kyber_shared_secret = self.kem.encap_secret(server_kyber_pub_bytes)
        print(f"  - Kyber512 encapsulated: ct={len(kyber_ciphertext)} bytes, ss={len(kyber_shared_secret)} bytes")

        # --- Phase 3: Hybrid Key Derivation via HKDF-SHA256 ---
        self.session_key = derive_hybrid_key(ecdh_shared_secret, kyber_shared_secret)
        key_fingerprint = self.session_key[:8].hex()
        print(f"{MAGENTA}[STEP 3/4]{RESET} HKDF-SHA256 Ratchet:")
        print(f"  - Derived 256-bit AES Session Key: {GREEN}{self.session_key.hex()[:24]}...{RESET}")
        print(f"  - Fingerprint: {GREEN}{key_fingerprint}{RESET}")

        # --- Phase 4: Send Handshake Reply ---
        reply_packet = {
            "type": "handshake_reply",
            "username": self.username,
            "client_ecdh_pub": b64encode(client_ecdh_pub_bytes),
            "kyber_ciphertext": b64encode(kyber_ciphertext),
        }
        await self.ws.send(json.dumps(reply_packet))

        # Await completion ack
        raw_ack = await self.ws.recv()
        ack_data = json.loads(raw_ack)
        if ack_data.get("type") == "handshake_complete":
            print(f"{GREEN}{BOLD}[STEP 4/4] Handshake Complete! Secured with AES-256-GCM.{RESET}")
            print(f"{YELLOW}Type a message and press Enter. Type '/quit' to exit.{RESET}\n")
            return True
        else:
            print(f"{RED}[ERROR]{RESET} Handshake ack failed: {ack_data}")
            return False

    async def send_encrypted(self, plaintext: str):
        if not self.session_key or not self.ws:
            return
        encrypted_bytes = encrypt_message(self.session_key, plaintext)
        packet = {
            "type": "encrypted_msg",
            "username": self.username,
            "payload": b64encode(encrypted_bytes),
        }
        await self.ws.send(json.dumps(packet))

    async def listen_loop(self):
        try:
            async for raw_message in self.ws:
                data = json.loads(raw_message)
                mtype = data.get("type")

                if mtype == "chat_msg":
                    sender = data.get("sender", "Unknown")
                    payload_b64 = data.get("payload", "")
                    try:
                        decrypted_text = decrypt_message(self.session_key, b64decode(payload_b64))
                        print(f"\r{CYAN}[{sender}]{RESET}: {decrypted_text}")
                    except Exception as err:
                        print(f"\r{RED}[DECRYPT FAILED from {sender}]: {err}{RESET}")
                    print(f"{BOLD}> {RESET}", end="", flush=True)

                elif mtype == "system":
                    print(f"\r{YELLOW}[i] {data.get('text')}{RESET}")
                    print(f"{BOLD}> {RESET}", end="", flush=True)

        except Exception as e:
            if self.running:
                print(f"\n{RED}[DISCONNECTED]{RESET} Connection closed: {e}")
        finally:
            self.running = False

    async def run_interactive(self):
        if not await self.connect_and_handshake():
            return

        listen_task = asyncio.create_task(self.listen_loop())

        loop = asyncio.get_running_loop()
        try:
            while self.running:
                print(f"{BOLD}> {RESET}", end="", flush=True)
                # Read line asynchronously from stdin
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                text = line.strip()
                if not text:
                    continue
                if text.lower() in ("/quit", "/exit"):
                    print(f"{YELLOW}Exiting chat...{RESET}")
                    break

                await self.send_encrypted(text)

        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            self.running = False
            listen_task.cancel()
            if self.ws:
                await self.ws.close()
            if self.kem:
                self.kem.free()

    async def run_demo(self, test_message: str = "Quantum greetings! Hybrid PQC verified."):
        if not await self.connect_and_handshake():
            return False

        print(f"\n{BOLD}[DEMO MODE]{RESET} Sending test message:")
        print(f"  \"{test_message}\"")
        await self.send_encrypted(test_message)

        # Wait up to 5 seconds for response
        try:
            while True:
                raw = await asyncio.wait_for(self.ws.recv(), timeout=5.0)
                data = json.loads(raw)
                if data.get("type") == "chat_msg":
                    sender = data.get("sender")
                    decrypted = decrypt_message(self.session_key, b64decode(data.get("payload")))
                    print(f"\n{GREEN}[RECEIVED & DECRYPTED from {sender}]:{RESET}")
                    print(f"  \"{decrypted}\"")
                    print(f"\n{GREEN}{BOLD}[OK] Demo verification successful! PQC channel operational.{RESET}\n")
                    return True
                elif data.get("type") == "system":
                    print(f"  {YELLOW}[i] {data.get('text')}{RESET}")
        except asyncio.TimeoutError:
            print(f"{YELLOW}[DEMO] Message sent, timed out waiting for reply.{RESET}")
            return True
        finally:
            if self.ws:
                await self.ws.close()
            if self.kem:
                self.kem.free()


def main():
    parser = argparse.ArgumentParser(description="Hybrid PQC Chat WebSocket Client")
    parser.add_argument(
        "--server",
        default="ws://127.0.0.1:8000/ws/chat",
        help="WebSocket URL (e.g., ws://localhost:8000/ws/chat or wss://<app>.onrender.com/ws/chat)",
    )
    parser.add_argument(
        "--username",
        default=f"CLI-{secrets.token_hex(2).upper()}",
        help="Username for the chat session",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run a quick automated round-trip demo and exit",
    )
    parser.add_argument(
        "--message",
        type=str,
        default=None,
        help="Send a single message in demo mode and exit",
    )

    args = parser.parse_args()
    client = PQCWebSocketClient(args.server, args.username)

    if args.demo or args.message:
        msg = args.message or "Quantum greetings! Hybrid PQC channel verified."
        success = asyncio.run(client.run_demo(msg))
        sys.exit(0 if success else 1)
    else:
        asyncio.run(client.run_interactive())


if __name__ == "__main__":
    main()
