"""
server.py — Hybrid PQC Chat Server
Performs a hybrid ECDH + Kyber512 key exchange with the client,
derives a shared AES-256-GCM session key, then exchanges one
encrypted message round-trip to prove the channel is live.
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
# Wire-protocol helper: length-prefix framing
# TCP is a stream protocol — it has no built-in message boundaries.
# We prefix every blob with a 4-byte big-endian length so the receiver
# knows exactly how many bytes to read for each logical message.
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
# Handshake — server side
# Step-by-step hybrid key exchange:
#   1. Server generates ECDH + Kyber512 key pairs
#   2. Sends both public keys to client
#   3. Receives client ECDH public key + Kyber ciphertext
#   4. Computes ECDH shared secret via ECDH exchange
#   5. Decapsulates Kyber ciphertext → Kyber shared secret
#   6. Derives final session key with HKDF
# ---------------------------------------------------------------------------
def run_server():
    # --- Key generation ---
    print("[SERVER] Generating ECDH key pair...")
    ecdh_private_key, ecdh_pub_bytes = generate_ecdh_keypair()

    print("[SERVER] Generating Kyber512 key pair...")
    # Kyber512 is NIST PQC Round 3 winner (ML-KEM-512 in FIPS 203).
    # "512" refers to the security parameter, giving ~128-bit post-quantum security.
    kem = oqs.KeyEncapsulation("Kyber512")
    kyber_pub_bytes = kem.generate_keypair()   # also stores private key internally

    # --- TCP server setup ---
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"[SERVER] Listening on {HOST}:{PORT} ...")

        conn, addr = srv.accept()
        print(f"[SERVER] Connection from {addr}")

        with conn:
            # Step 1 — Send server's ECDH public key
            print("[SERVER] Sending ECDH public key...")
            send_blob(conn, ecdh_pub_bytes)

            # Step 2 — Send server's Kyber512 public key
            print("[SERVER] Sending Kyber512 public key...")
            send_blob(conn, kyber_pub_bytes)

            # Step 3 — Receive client's ECDH public key
            client_ecdh_pub_bytes = recv_blob(conn)
            print(f"[SERVER] Received client ECDH public key ({len(client_ecdh_pub_bytes)} bytes)")

            # Step 4 — Receive Kyber ciphertext produced by client encapsulation
            kyber_ciphertext = recv_blob(conn)
            print(f"[SERVER] Received Kyber ciphertext ({len(kyber_ciphertext)} bytes)")

            # --- Compute ECDH shared secret ---
            # Load the client's public key from DER bytes and run ECDH.
            client_ecdh_pub = serialization.load_der_public_key(client_ecdh_pub_bytes)
            ecdh_shared_secret = ecdh_private_key.exchange(ECDH(), client_ecdh_pub)
            print(f"[SERVER] ECDH shared secret derived ({len(ecdh_shared_secret)} bytes)")

            # --- Kyber decapsulation ---
            # kem.decap_secret() uses the stored private key to recover the same
            # random secret the client generated during encapsulation.
            kyber_shared_secret = kem.decap_secret(kyber_ciphertext)
            print(f"[SERVER] Kyber shared secret decapsulated ({len(kyber_shared_secret)} bytes)")

            # --- Hybrid key derivation ---
            session_key = derive_hybrid_key(ecdh_shared_secret, kyber_shared_secret)
            print(f"[SERVER] Hybrid session key derived: {session_key.hex()}")

            # --- Receive and decrypt client's message ---
            encrypted_msg = recv_blob(conn)
            plaintext = decrypt_message(session_key, encrypted_msg)
            print(f"[SERVER] Decrypted message from client: \"{plaintext}\"")

            # --- Send encrypted reply ---
            reply = "Hello from the server! Hybrid PQC handshake complete."
            encrypted_reply = encrypt_message(session_key, reply)
            send_blob(conn, encrypted_reply)
            print("[SERVER] Encrypted reply sent.")

    kem.free()


if __name__ == "__main__":
    run_server()
