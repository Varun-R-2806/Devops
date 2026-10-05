"""
client.py — Hybrid PQC Chat Client
Connects to the server, performs a hybrid ECDH + Kyber512 key exchange,
derives the matching AES-256-GCM session key, then sends one encrypted
test message and decrypts the server's reply.
"""

import socket
import struct

import oqs  # liboqs-python

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDH

from crypto_utils import (
    generate_ecdh_keypair,
    derive_hybrid_key,
    encrypt_message,
    decrypt_message,
)

HOST = "127.0.0.1"
PORT = 9999


# ---------------------------------------------------------------------------
# Wire-protocol helper — mirrors the server's length-prefix framing exactly.
# Both sides must use the same framing or they will misread message boundaries.
# ---------------------------------------------------------------------------
def send_blob(sock: socket.socket, data: bytes):
    """Send len-prefixed bytes over a socket."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_blob(sock: socket.socket) -> bytes:
    """Receive a len-prefixed blob from a socket."""
    raw_len = _recvall(sock, 4)
    length = struct.unpack(">I", raw_len)[0]
    return _recvall(sock, length)


def _recvall(sock: socket.socket, n: int) -> bytes:
    """Keep reading until exactly n bytes have been received."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Handshake — client side
# The client's role in the hybrid exchange:
#   1. Generate own ECDH key pair
#   2. Receive server ECDH + Kyber public keys
#   3. Compute ECDH shared secret
#   4. Encapsulate against server's Kyber public key → (ciphertext, kyber_secret)
#   5. Send own ECDH public key + Kyber ciphertext to server
#   6. Derive session key with the same HKDF call
# ---------------------------------------------------------------------------
def run_client():
    # --- Generate client ECDH key pair ---
    print("[CLIENT] Generating ECDH key pair...")
    ecdh_private_key, ecdh_pub_bytes = generate_ecdh_keypair()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print(f"[CLIENT] Connected to {HOST}:{PORT}")

        # Step 1 — Receive server's ECDH public key
        server_ecdh_pub_bytes = recv_blob(sock)
        print(f"[CLIENT] Received server ECDH public key ({len(server_ecdh_pub_bytes)} bytes)")

        # Step 2 — Receive server's Kyber512 public key
        kyber_server_pub_bytes = recv_blob(sock)
        print(f"[CLIENT] Received server Kyber512 public key ({len(kyber_server_pub_bytes)} bytes)")

        # --- Compute ECDH shared secret ---
        # Load the server's DER-encoded public key and perform ECDH exchange.
        server_ecdh_pub = serialization.load_der_public_key(server_ecdh_pub_bytes)
        ecdh_shared_secret = ecdh_private_key.exchange(ECDH(), server_ecdh_pub)
        print(f"[CLIENT] ECDH shared secret derived ({len(ecdh_shared_secret)} bytes)")

        # --- Kyber512 encapsulation ---
        # encap_secret() generates a fresh random secret, encrypts it under the
        # server's public key, and returns (ciphertext, shared_secret).
        # Only the holder of the server's Kyber private key can recover the secret.
        kem = oqs.KeyEncapsulation("Kyber512")
        kyber_ciphertext, kyber_shared_secret = kem.encap_secret(kyber_server_pub_bytes)
        print(f"[CLIENT] Kyber secret encapsulated (ct={len(kyber_ciphertext)} bytes, ss={len(kyber_shared_secret)} bytes)")

        # Step 3 — Send client's ECDH public key
        print("[CLIENT] Sending ECDH public key...")
        send_blob(sock, ecdh_pub_bytes)

        # Step 4 — Send Kyber ciphertext so server can decapsulate
        print("[CLIENT] Sending Kyber ciphertext...")
        send_blob(sock, kyber_ciphertext)

        # --- Hybrid key derivation ---
        # Use the SAME order as the server: ECDH secret first, Kyber second.
        # Swapping the order would produce a different key and break decryption.
        session_key = derive_hybrid_key(ecdh_shared_secret, kyber_shared_secret)
        print(f"[CLIENT] Hybrid session key derived: {session_key.hex()}")

        # --- Send encrypted test message ---
        test_message = "Hello from the client! This message is post-quantum secured."
        encrypted_msg = encrypt_message(session_key, test_message)
        send_blob(sock, encrypted_msg)
        print(f"[CLIENT] Sent encrypted message: \"{test_message}\"")

        # --- Receive and decrypt server reply ---
        encrypted_reply = recv_blob(sock)
        reply = decrypt_message(session_key, encrypted_reply)
        print(f"[CLIENT] Decrypted server reply: \"{reply}\"")

    kem.free()


if __name__ == "__main__":
    run_client()
