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
| Per-packet authentication | Ed25519 signature (or HMAC-SHA-512 fast path) |
| Payload confidentiality + integrity | AES-256-GCM authenticated encryption |
| Replay-attack prevention | Timestamp bounds (±30 s) + per-session sequence-number window |
| Cryptographic device identity | SHA-256 of Ed25519 public key (not IP/MAC) |
| Forward secrecy | X25519 ephemeral key exchange per session |
| Key derivation | HKDF-SHA-256 binding sender + recipient IDs |
| Trust bootstrap | TOFU → fingerprint → web-of-trust endorsements + QR exchange |
| Transport agnostic | Runs over UDP, in-process, BLE, LoRa, WebRTC, … |
| Mesh routing | Identity-based forwarding, trust-weighted route selection |
| Reliable delivery | Stop-and-wait ARQ with exponential-backoff retransmission |
| MAC optimization | HMAC-SHA-512 DATA path replaces Ed25519 per packet (~4–40× faster) |

---

## Protocol Innovations

### 1 — Trust Bootstrap Layer

Most protocols fail at first contact. ZTLNP provides a four-level trust model:

| Level | How obtained |
|---|---|
| `UNKNOWN` | Never seen (rejected unless TOFU is enabled) |
| `TOFU` | Key accepted on first use |
| `VERIFIED` | Human confirmed key fingerprint out-of-band |
| `ENDORSED` | A VERIFIED peer signed a web-of-trust voucher |

**Fingerprints** are SHA-256(Ed25519 pub key) formatted as eight groups of four
uppercase hex chars (`A1B2:C3D4:…`) — easy to read over a phone call.

**QR payloads** encode `ZTLNP:1:<device_id_hex>:<pub_hex>:<fingerprint_hex>` so
any QR scanner can bootstrap a VERIFIED key.

**Web-of-trust endorsements** are 160-byte blobs:
`[endorser_id][target_id][target_pub]` + 64-byte Ed25519 signature from the
endorser.  Any `TrustStore` with the endorser's VERIFIED key can validate them.

### 2 — Transport Abstraction

The entire protocol stack is decoupled from the physical medium via the
`Transport` ABC:

```
Transport.send(dest_addr, data)
Transport.recv(timeout) → (src_addr, data)
```

Provided implementations:
- **`InProcessTransport`** — in-memory queue (tests / simulation)
- **`UdpTransport`** — standard UDP socket

Adding BLE, LoRa, or WebRTC requires only a new `Transport` subclass.

### 3 — Mesh Routing (Identity-Based)

`Router` maintains a `RouteTable` keyed by **device identity**, not IP:

* Route entries include `hop_count`, `trust_score`, and `latency_ms`.
* Best route selected by score = `trust_score / (hop_count × latency_ms)`.
* `ROUTE_ANNOUNCE` packets flood reachability; each hop increments the count
  and the path trust decays by 10% per hop.
* Forwarding is transparent: the final recipient verifies the *original*
  sender's Ed25519 signature regardless of path.

### 4 — Reliability (Stop-and-Wait ARQ)

`ReliableChannel` adds guaranteed delivery on top of any established session:

* Pending-packet queue keyed by sequence number.
* Exponential backoff: timeouts double on each retry (configurable ceiling).
* `get_retransmissions()` returns overdue packets; caller decides when to
  poll (no hidden threads).
* `RetransmitError` raised after `max_retries` attempts.

### 5 — MAC Optimization (Performance Fast Path)

Ed25519 per packet is secure but expensive. For **established sessions** ZTLNP
offers an HMAC-SHA-512 fast path:

* A 64-byte MAC key is derived from the same X25519 shared secret via HKDF
  with a *different* info string (cryptographically independent of the
  session key).
* `build_data_packet_mac()` / `MAC_AUTH` flag select this path.
* Wire format unchanged: the 64-byte `signature` field carries the HMAC tag.
* Same replay protection (timestamp + sequence window) applies.
* Measured 4–40× faster depending on hardware.

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
                                 ROUTE_ANNOUNCE=0x07  TRUST_ENDORSE=0x08
     6       2  Flags            bit 0: ENCRYPTED  bit 1: BROADCAST
                                 bit 2: MAC_AUTH (signature field = HMAC-SHA-512)
     8      32  Sender ID        SHA-256 of sender's Ed25519 public key
    40      32  Recipient ID     SHA-256 of recipient's Ed25519 public key
    72       8  Timestamp        Unix milliseconds
    80       4  Sequence Number  monotonically increasing per sender
    84      12  Nonce            AES-256-GCM nonce (random per packet)
    96       4  Payload Length   bytes that follow
   100       N  Payload          AES-256-GCM ciphertext (plaintext for HELLO)
 100+N      64  Signature        Ed25519 over bytes [0 .. 100+N)
                                 — or HMAC-SHA-512 when MAC_AUTH flag is set
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
| Session key derivation | HKDF-SHA-256 | `cryptography` |
| MAC key derivation | HKDF-SHA-256 (separate info string) | `cryptography` |
| Payload encryption | AES-256-GCM | `cryptography` |
| Fast packet MAC | HMAC-SHA-512 | `cryptography` |

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
├── crypto.py        CryptoEngine (Ed25519, X25519, HKDF, AES-GCM, HMAC-SHA-512)
├── device.py        Device — identity, session management, packet builders
├── session.py       Session — session/MAC keys, sequence tracking, replay window
├── protocol.py      Protocol — state machine (IDLE → ESTABLISHED → CLOSED)
├── exceptions.py    Custom exception hierarchy
├── trust.py         Trust bootstrap (TOFU, fingerprint, QR, web-of-trust)
├── transport.py     Transport ABC, InProcessTransport, UdpTransport
├── router.py        Router, RouteTable, RouteEntry (mesh routing)
└── reliability.py   ReliableChannel (ARQ retransmission, exponential backoff)

tests/
├── test_packet.py       Packet serialisation, wire layout, error paths
├── test_crypto.py       Cryptographic primitive unit tests
├── test_protocol.py     Handshake, data exchange, security properties
├── test_trust.py        Trust bootstrap: TOFU, fingerprint, QR, web-of-trust
├── test_transport.py    InProcessTransport and UdpTransport
├── test_router.py       RouteTable, Router, mesh routing, announcements
└── test_reliability.py  ReliableChannel ARQ, retransmission, MAC optimization

example.py           End-to-end demo covering all five features
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
* **Every packet proves its origin** — the Ed25519 signature (or HMAC-SHA-512
  tag for data packets) is unforgeable without the sender's key material.
* **Replay attacks fail** — the timestamp and sequence-number window ensure
  that captured packets cannot be re-delivered.
* **Passive eavesdropping fails** — AES-256-GCM provides confidentiality even
  against an observer on the same LAN segment.
* **First contact is safe** — TOFU, QR verification, and web-of-trust
  endorsements solve the key-distribution problem most protocols ignore.
* **Works on any medium** — the Transport abstraction means ZTLNP can run over
  UDP, BLE, LoRa, serial links, or anything else without protocol changes.
* **Scales to meshes** — identity-based routing enables multi-hop forwarding
  without IP infrastructure.
