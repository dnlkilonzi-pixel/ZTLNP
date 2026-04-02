# ZTLNP — Zero-Trust Local Network Protocol

A custom network protocol that **authenticates every packet** and trusts
nothing by default — not even hosts on the same LAN.

Current TCP/IP implicitly trusts everything on the local network. ZTLNP
redesigns that assumption: every device proves its identity cryptographically
on every packet it sends.

---

## Key Properties

| Property | Mechanism |
|---|---|
| Per-packet authentication | Ed25519 signature over the entire packet |
| Payload confidentiality + integrity | AES-256-GCM authenticated encryption |
| Replay-attack prevention | Timestamp bounds (±30 s) + per-session sequence-number window |
| Cryptographic device identity | SHA-256 of Ed25519 public key (not IP/MAC) |
| Forward secrecy | X25519 ephemeral key exchange per session |
| Key derivation | HKDF-SHA-256 binding sender + recipient IDs |

---

## Packet Wire Format

All multi-byte integers are big-endian.

```
Offset  Length  Field
------  ------  -----
     0       4  Magic            b"ZTLP"
     4       1  Version          0x01
     5       1  Type             HELLO=0x01  KEY_EXCHANGE=0x02  DATA=0x03
                                 ACK=0x04    ERROR=0x05          BYE=0x06
     6       2  Flags            bit 0: ENCRYPTED  bit 1: BROADCAST
     8      32  Sender ID        SHA-256 of sender's Ed25519 public key
    40      32  Recipient ID     SHA-256 of recipient's Ed25519 public key
    72       8  Timestamp        Unix milliseconds
    80       4  Sequence Number  monotonically increasing per sender
    84      12  Nonce            AES-256-GCM nonce (random per packet)
    96       4  Payload Length   bytes that follow
   100       N  Payload          AES-256-GCM ciphertext (plaintext for HELLO)
 100+N      64  Signature        Ed25519 over bytes [0 .. 100+N)
```

HELLO packets carry an **unencrypted** payload (`[32 B Ed25519 pub][32 B X25519 pub]`)
so that peers can bootstrap a shared secret. Every other packet type carries
an **encrypted** payload.

---

## Handshake Flow

```
Alice (initiator)                       Bob (responder)
─────────────────                       ───────────────
generate identity key pair              generate identity key pair
generate X25519 ephemeral key           generate X25519 ephemeral key

── HELLO (Ed25519 pub + X25519 pub) ──► receive, verify Ed25519 sig
                                        generate own X25519 ephemeral key

◄── HELLO (Ed25519 pub + X25519 pub) ── verify Ed25519 sig
X25519 DH → shared secret               X25519 DH → shared secret
HKDF → session key                      HKDF → session key

── KEY_EXCHANGE (AES-GCM "OK") ────────► verify sig, replay check,
                                         decrypt, confirm key match
◄── KEY_EXCHANGE (AES-GCM "OK") ───────  verify sig, replay check,
                                          decrypt

        ══════════ ESTABLISHED ══════════

── DATA (AES-GCM ciphertext) ──────────► verify sig, replay check, decrypt
◄── ACK ────────────────────────────────

── BYE ─────────────────────────────────► session closed
```

---

## Cryptographic Algorithms

| Purpose | Algorithm | Library |
|---|---|---|
| Identity / signing | Ed25519 | `cryptography` |
| Key agreement | X25519 | `cryptography` |
| Key derivation | HKDF-SHA-256 | `cryptography` |
| Payload encryption | AES-256-GCM | `cryptography` |

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Quick Start

```python
from ztlnp.device import Device
from ztlnp.protocol import Protocol, ProtocolState

alice_dev = Device("Alice")
bob_dev   = Device("Bob")

alice = Protocol(alice_dev)
bob   = Protocol(bob_dev)

# ── Handshake ──────────────────────────────────────────────────────
hello1 = alice.initiate(bob_dev.device_id)   # Alice → Bob HELLO
hello2 = bob.process_incoming(hello1)        # Bob   → Alice HELLO
ke1    = alice.process_incoming(hello2)      # Alice → Bob KEY_EXCHANGE
ke2    = bob.process_incoming(ke1)           # Bob   → Alice KEY_EXCHANGE
alice.process_incoming(ke2)                  # Alice confirms

assert alice.state == ProtocolState.ESTABLISHED
assert bob.state   == ProtocolState.ESTABLISHED

# ── Data exchange ──────────────────────────────────────────────────
wire      = alice.send_data(b"zero-trust message")
plaintext = bob.receive_data(wire)
assert plaintext == b"zero-trust message"
```

Run the full demo:

```bash
python example.py
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Project Structure

```
ztlnp/
├── __init__.py      Public API re-exports
├── packet.py        Wire-format packet (Packet, PacketType, PacketFlags)
├── crypto.py        CryptoEngine (Ed25519, X25519, HKDF, AES-GCM)
├── device.py        Device — identity, session management, packet builders
├── session.py       Session — session key, sequence tracking, replay window
├── protocol.py      Protocol — state machine (IDLE → ESTABLISHED → CLOSED)
└── exceptions.py    Custom exception hierarchy

tests/
├── test_packet.py   Packet serialisation, wire layout, error paths
├── test_crypto.py   Cryptographic primitive unit tests
└── test_protocol.py Handshake, data exchange, security properties

example.py           End-to-end demo script
requirements.txt     Python dependencies
```

---

## Why This Matters

Traditional TCP/IP networks assume that anything already on the LAN is
trustworthy — an attacker who gains access to the local network can intercept
or inject traffic freely.

ZTLNP removes that assumption:

* **No IP trust** — identity is a cryptographic key, not an IP address.
* **No MAC trust** — MAC addresses are trivially spoofable and ignored.
* **Every packet proves its origin** — the Ed25519 signature is unforgeable
  without the sender's private key.
* **Replay attacks fail** — the timestamp and sequence-number window ensure
  that captured packets cannot be re-delivered.
* **Passive eavesdropping fails** — AES-256-GCM provides confidentiality even
  against an observer on the same LAN segment.
