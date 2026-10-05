"""
crypto_utils.py — Cryptographic primitives for Hybrid PQC Chat
Combines classical ECDH (SECP256R1) and post-quantum Kyber512
to produce a single AES-256-GCM session key.
"""

import os
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
    ECDH,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# ECDH key-pair generation
# We use SECP256R1 (P-256) — the most widely deployed elliptic curve and
# a NIST-approved baseline for classical key agreement.
# ---------------------------------------------------------------------------
def generate_ecdh_keypair():
    """
    Generate an ephemeral ECDH private/public key pair on SECP256R1.
    Returns (private_key, public_key_bytes).
    Public key is serialized as uncompressed DER/SubjectPublicKeyInfo so
    it can be sent over the wire and reconstructed on the other side.
    """
    private_key = generate_private_key(SECP256R1())
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key_bytes


# ---------------------------------------------------------------------------
# Hybrid key derivation
# We concatenate both shared secrets before feeding them to HKDF so that
# the final key is secure as long as EITHER primitive is unbroken.
# HKDF-SHA256 is the standard way to turn raw Diffie-Hellman output into
# a properly random, fixed-length symmetric key.
# ---------------------------------------------------------------------------
def derive_hybrid_key(ecdh_shared_secret: bytes, kyber_shared_secret: bytes) -> bytes:
    """
    Derive a 32-byte AES-256 session key from:
      - ecdh_shared_secret : raw bytes from classical ECDH exchange
      - kyber_shared_secret: raw bytes from Kyber512 KEM
    Concatenates both secrets as HKDF input keying material (IKM).
    Using a fixed info tag ties the key to this specific protocol.
    """
    ikm = ecdh_shared_secret + kyber_shared_secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,          # no salt → HKDF uses a zero-filled salt of hash length
        info=b"hybrid-pqc-chat-v1",
    )
    return hkdf.derive(ikm)


# ---------------------------------------------------------------------------
# AES-256-GCM encryption
# GCM provides authenticated encryption (confidentiality + integrity in one
# pass), which means tampering with the ciphertext will be detected before
# any plaintext is returned.  The 12-byte random nonce must be unique per
# message; we prepend it to the output so the receiver can extract it.
# ---------------------------------------------------------------------------
def encrypt_message(key: bytes, plaintext: str) -> bytes:
    """
    Encrypt a plaintext string with AES-256-GCM.
    Returns nonce (12 B) + ciphertext+tag as a single bytes object.
    The tag (16 B) is appended automatically by AESGCM.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)          # 96-bit nonce — standard for GCM
    ct_and_tag = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ct_and_tag       # receiver needs the nonce to decrypt


# ---------------------------------------------------------------------------
# AES-256-GCM decryption
# Splits the wire format back into nonce and ciphertext+tag, then
# authenticates and decrypts in one step.  Raises InvalidTag if the
# message was tampered with.
# ---------------------------------------------------------------------------
def decrypt_message(key: bytes, data: bytes) -> str:
    """
    Decrypt AES-256-GCM data produced by encrypt_message().
    data must be: nonce (12 B) || ciphertext+tag.
    Raises cryptography.exceptions.InvalidTag on authentication failure.
    """
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ct_and_tag = data[12:]
    plaintext_bytes = aesgcm.decrypt(nonce, ct_and_tag, None)
    return plaintext_bytes.decode()
