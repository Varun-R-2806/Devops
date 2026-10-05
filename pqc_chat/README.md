# Hybrid Post-Quantum Cryptography (PQC) Secured Chat

A minimal, working demonstration of a **hybrid key exchange** that combines
classical elliptic-curve Diffie-Hellman (ECDH) with the post-quantum Key
Encapsulation Mechanism (KEM) **Kyber512**, producing a single AES-256-GCM
session key for encrypted messaging.

---

## Why Hybrid (Classical + PQC)?

| Threat | Classical ECDH alone | Kyber512 alone | Hybrid |
|---|---|---|---|
| Today's adversaries | ✅ Secure | ✅ Secure | ✅ Secure |
| Future quantum computer (Shor's algorithm) | ❌ Broken | ✅ Secure | ✅ Secure |
| Undiscovered flaw in Kyber | ✅ Secure | ❌ Broken | ✅ Secure |

A hybrid scheme is secure **as long as at least one** of the two primitives
remains unbroken. This is the recommended transition strategy from NIST,
ETSI, and the German BSI during the current migration period to PQC standards.

---

## Dependencies

```bash
pip install liboqs-python cryptography
```

> `liboqs-python` requires the native `liboqs` shared library to be installed.
> See [open-quantum-safe/liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
> for platform-specific installation instructions.

---

## How to Run

Open **two terminals** in this directory:

**Terminal 1 — Start the server first:**
```bash
python server.py
```

**Terminal 2 — Run the client:**
```bash
python client.py
```

Expected output: both sides print the derived session key (identical hex string),
the client's plaintext message appears on the server, and the server's reply
appears on the client.

---

## Architecture — Handshake Steps (in order)

```
CLIENT                                          SERVER
  |                                               |
  |  1. Server generates ECDH keypair             |
  |     Server generates Kyber512 keypair         |
  |                                               |
  |<---- server_ecdh_pub_key (DER) --------------|  (2)
  |<---- kyber_server_pub_key (raw bytes) --------|  (3)
  |                                               |
  |  4. Client generates ECDH keypair             |
  |  5. Client computes ECDH shared secret        |
  |     (client_ecdh_priv × server_ecdh_pub)      |
  |  6. Client encapsulates kyber_server_pub_key  |
  |     → (kyber_ciphertext, kyber_shared_secret) |
  |                                               |
  |---- client_ecdh_pub_key (DER) -------------->|  (7)
  |---- kyber_ciphertext ----------------------->|  (8)
  |                                               |
  |  9. Server computes ECDH shared secret        |
  |     (server_ecdh_priv × client_ecdh_pub)      |
  | 10. Server decapsulates kyber_ciphertext      |
  |     → kyber_shared_secret                     |
  |                                               |
  | CLIENT & SERVER both run:                     |
  | session_key = HKDF(ecdh_secret || kyber_secret, info="hybrid-pqc-chat-v1")
  |                                               |
  |---- AES-256-GCM(session_key, message) ------>| (11)
  |<---- AES-256-GCM(session_key, reply) ---------|  (12)
```

### Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Classical KEM | ECDH (SECP256R1 / P-256) | NIST-approved, universally supported, ~128-bit classical security |
| PQC KEM | Kyber512 | NIST FIPS 203 winner (ML-KEM); ~128-bit post-quantum security; fastest PQC KEM in practice |
| Key derivation | HKDF-SHA256 | Standardized (RFC 5869); extracts and expands raw DH output into a uniform key; domain-separated via `info` tag |
| Symmetric cipher | AES-256-GCM | Authenticated encryption (AEAD); single-pass confidentiality + integrity; hardware-accelerated on modern CPUs |
| Framing | 4-byte length prefix | TCP is a stream; length-prefixing gives reliable message boundaries without external framing libraries |
| Nonce | 12-byte random per message | 96-bit GCM nonce is the NIST recommendation; random nonce is safe for single-session demos |

---

## File Structure

```
pqc_chat/
├── crypto_utils.py   # ECDH keygen, HKDF derivation, AES-GCM encrypt/decrypt
├── server.py         # TCP server: hybrid handshake + message receive/reply
├── client.py         # TCP client: hybrid handshake + message send/receive
└── README.md         # This file
```
