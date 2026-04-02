# ZTLNP Protocol Specification

```
Working Group:   ZTLNP                          Category: Experimental
Internet-Draft:  draft-ztlnp-protocol-01        ISSN: (pending)
Intended Status: Proposed Standard
Expires:         October 2026
Created:         April 2026
```

**Title:**  Zero Trust Local Network Protocol (ZTLNP), Version 1  
**Status:** DRAFT — open for community review and comment  
**Revision:** 01  
**Authors:** ZTLNP Project  
**Repository:** https://github.com/dnlkilonzi-pixel/ZTLNP  
**Companion documents:**
- [Threat Model](docs/threat-model.md)
- [Performance Benchmarks](docs/performance-benchmarks.md)
- [Security Analysis](docs/security-analysis.md)

---

> **Copyright Notice**
>
> This document is released under the Creative Commons Attribution 4.0
> International License (CC BY 4.0).  Implementations are free to adopt
> this specification without royalty.

---

## Abstract

The Zero Trust Local Network Protocol (ZTLNP) is an application-layer
security protocol that provides cryptographic authentication, confidentiality,
integrity, replay protection, and trust management for packet-level
communication between identified devices.  Unlike traditional LAN protocols,
ZTLNP trusts nothing by default: every packet must carry a cryptographic proof
of origin regardless of where it originated on the network.

---

## Status of This Memo

This is an Internet-Draft in the spirit of the IETF process, but produced
outside the IETF.  It is submitted for informational purposes and community
review.  Distribution is unlimited.

Internet-Drafts are working documents.  They may be updated, replaced, or
obsoleted by other documents at any time.  It is inappropriate to use
Internet-Drafts as reference material or to cite them other than as
"work in progress."

---

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
[BCP 14] (RFC 2119, RFC 8174) when, and only when, they appear in all
capitals, as shown here.

---

## Table of Contents

1. Introduction
2. Terminology
3. Cryptographic Primitives
4. Wire Format
5. Packet Types
6. State Machine
7. Handshake Protocol
8. Data Transfer
9. Trust Bootstrap Layer
10. Identity Rotation
11. Mesh Routing
12. Reliable Delivery
13. Traffic Analysis Resistance
14. Security Considerations
15. Threat Model
16. Formal Security Properties
17. IANA Considerations
18. References
19. Appendix A: Test Vectors
20. Appendix B: Known Limitations
21. Appendix C: Change Log

---

## 1. Introduction

### 1.1 Motivation

Conventional TCP/IP networks grant implicit trust to hosts that share a
physical or virtual LAN segment.  An attacker with access to the local network
can intercept, inject, or replay packets without any cryptographic barrier.

ZTLNP removes this implicit trust.  Every packet carries:

- the sender's cryptographic identity (Ed25519 public key hash),
- a per-packet or per-session authentication tag, and
- an encrypted, authenticated payload (AES-256-GCM).

No IP address, MAC address, VLAN tag, or network topology fact is trusted.

### 1.2 Design Principles

1. **Zero trust by default** — unknown devices are rejected unless TOFU is
   explicitly enabled.
2. **Identity before routing** — devices are identified by public-key hashes,
   not by network addresses.
3. **Transport agnosticism** — the protocol specification is independent of
   the underlying medium (UDP, BLE, LoRa, WebRTC, …).
4. **Forward secrecy** — session keys are derived from ephemeral X25519
   exchanges; compromise of the long-term identity key does not expose past
   sessions.
5. **Minimal trust surface** — the only trusted operation is verifying a
   cryptographic signature or HMAC tag.

---

## 2. Terminology

| Term | Definition |
|---|---|
| **Device ID** | 32-byte SHA-256 of a device's Ed25519 public key |
| **Session key** | 32-byte AES-256-GCM key derived per session |
| **MAC key** | 64-byte HMAC-SHA-512 key derived per session (fast path) |
| **TOFU** | Trust On First Use: accept a key on first contact |
| **VERIFIED** | A key whose fingerprint was confirmed out-of-band |
| **ENDORSED** | A key vouched for by at least one VERIFIED peer |
| **ARQ** | Automatic Repeat reQuest: retransmit lost packets |
| **SACK** | Selective ACKnowledgement: acknowledge specific packets |
| **Cover traffic** | Dummy packets injected to obscure silence intervals |

---

## 3. Cryptographic Primitives

| Purpose | Algorithm | Key / Output Size |
|---|---|---|
| Identity key pair | Ed25519 | 32-byte private + 32-byte public |
| Session agreement | X25519 Diffie-Hellman | 32-byte shared secret |
| Session key derivation | HKDF-SHA-256, info=`ZTLNP-v1-session-key` | 32 bytes |
| MAC key derivation | HKDF-SHA-256, info=`ZTLNP-v1-mac-key` | 64 bytes |
| Payload encryption | AES-256-GCM | 32-byte key, 12-byte nonce, 16-byte tag |
| Per-packet MAC | HMAC-SHA-512 | 64-byte tag (truncated to 64 B signature field) |
| Device fingerprint | SHA-256(Ed25519 pub) | 32 bytes → 79-char colon-hex |
| Key transition | Ed25519 signature of 104-byte body | 64 bytes |

### 3.1 HKDF Salt

All HKDF operations use an empty salt.  The salt-free form provides the same
security as a uniformly random salt when the IKM (X25519 shared secret) is
computationally indistinguishable from uniform, which it is for X25519 with
Curve25519.

### 3.2 HKDF Info for Key Separation

The session key and MAC key are derived from the same X25519 shared secret
with **different** info strings, ensuring they are computationally
independent:

```
session_key = HKDF-SHA-256(
    IKM  = x25519_shared_secret,
    salt = "",
    info = b"ZTLNP-v1-session-key" + initiator_id + responder_id,
    len  = 32
)

mac_key = HKDF-SHA-256(
    IKM  = x25519_shared_secret,
    salt = "",
    info = b"ZTLNP-v1-mac-key" + initiator_id + responder_id,
    len  = 64
)
```

---

## 4. Wire Format

All multi-byte integer fields are big-endian (network byte order).

```
 Offset  Length  Field
 ------  ------  -----
      0       4  Magic           Constant b"ZTLP"
      4       1  Version         0x01
      5       1  Type            See Section 5
      6       2  Flags           See Section 4.1
      8      32  Sender ID       SHA-256(sender Ed25519 public key)
     40      32  Recipient ID    SHA-256(recipient Ed25519 public key)
                                 (all-zeros = broadcast)
     72       8  Timestamp       Milliseconds since Unix epoch (uint64)
     80       4  Sequence Num    Per-session monotonic counter (uint32)
     84      12  Nonce           AES-256-GCM nonce (random per packet)
     96       4  Payload Length  Number of payload bytes that follow (uint32)
    100       N  Payload         Encrypted ciphertext (or plaintext for HELLO)
  100+N      64  Signature       Ed25519 signature of bytes [0 .. 100+N)
                                 — or HMAC-SHA-512 tag when MAC_AUTH is set
```

Total minimum size: 164 bytes (zero-length payload).

### 4.1 Flags

| Bit | Mask | Name | Description |
|---|---|---|---|
| 0 | 0x0001 | ENCRYPTED | Payload is AES-256-GCM ciphertext |
| 1 | 0x0002 | BROADCAST | Addressed to all peers (Recipient ID = 0…0) |
| 2 | 0x0004 | MAC_AUTH | Signature field carries HMAC-SHA-512, not Ed25519 |
| 3 | 0x0008 | PADDING | Payload contains trailing padding bytes (strip after decrypt) |

### 4.2 Timestamp

The timestamp field encodes the sending time as milliseconds since the Unix
epoch.  Receivers MUST reject packets whose timestamp differs from the local
clock by more than 30 000 ms (30 seconds) in either direction.

### 4.3 Sequence Number

Each device maintains a per-session monotonically increasing 32-bit counter
for outgoing packets.  Receivers maintain a 64-entry replay window and reject
duplicate or excessively delayed sequence numbers.

---

## 5. Packet Types

| Value | Name | Direction | Description |
|---|---|---|---|
| 0x01 | HELLO | both | Announce identity + ephemeral X25519 key |
| 0x02 | KEY_EXCHANGE | both | Confirm derived session key |
| 0x03 | DATA | both | Encrypted application payload |
| 0x04 | ACK | both | Acknowledge a DATA or KEY_EXCHANGE packet |
| 0x05 | ERROR | both | Signal a protocol error |
| 0x06 | BYE | both | Graceful session teardown |
| 0x07 | ROUTE_ANNOUNCE | both | Advertise reachable device IDs (mesh) |
| 0x08 | TRUST_ENDORSE | both | Web-of-trust endorsement blob |
| 0x09 | KEY_ROTATE | both | Forward-secure identity key rotation |

### 5.1 HELLO Payload

```
[Ed25519 public key (32 B)][X25519 ephemeral public key (32 B)]
```

The HELLO payload is **unencrypted**.  Its Ed25519 signature is computed using
the sender's long-term identity key and covers all bytes in `signed_bytes()`
(header + payload).

### 5.2 KEY_EXCHANGE Payload

An AES-GCM encrypted confirmation message (plaintext: ASCII `"OK"`).  Both
sides send a KEY_EXCHANGE to confirm that they derived the same session key.

### 5.3 DATA Payload

AES-256-GCM ciphertext of the application plaintext.  If the PADDING flag is
set, the decrypted plaintext contains trailing padding bytes followed by a
1-byte pad-length field (see Section 13).

### 5.4 ACK Payload

In the stop-and-wait ARQ channel, an AES-GCM encrypted 4-byte (uint32)
sequence number of the acknowledged packet.

In the sliding-window ARQ channel, an AES-GCM encrypted SACK frame:

```
[sack_type (1 B)]  0x01 = cumulative, 0x02 = selective
[cum_ack   (4 B)]  Highest contiguous in-order sequence number
[n_blocks  (2 B)]  Number of SACK blocks
for each block:
    [left  (4 B)]  First sequence number in block
    [right (4 B)]  Last sequence number in block (inclusive)
```

### 5.5 ROUTE_ANNOUNCE Payload

Variable-length list of route advertisement entries:

```
[device_id (32 B)][hop_count (2 B, big-endian)] × N
```

### 5.6 KEY_ROTATE Payload

A 168-byte key transition blob (see Section 10):

```
[old_device_id    (32 B)]
[new_device_id    (32 B)]
[new_ed25519_pub  (32 B)]
[timestamp_ms     ( 8 B)]
[old_key_sig      (64 B)]   Ed25519 of the 104-byte body above
```

---

## 6. State Machine

```
                     ┌────────────────────────────────────┐
                     │                                    │
              ┌──────▼──────┐                             │
              │    IDLE     │                             │
              └──────┬──────┘                             │
                     │ initiate() / receive HELLO         │
              ┌──────▼──────┐                             │
              │ HELLO_SENT  │                             │
              └──────┬──────┘                             │
                     │ receive HELLO (responder) /        │
                     │ receive KEX (initiator)            │
              ┌──────▼──────┐                             │
              │ KEY_EXCHANGE│                             │
              └──────┬──────┘                             │
                     │ receive KEX confirmation           │
              ┌──────▼──────┐                             │
              │ ESTABLISHED │                             │
              └──────┬──────┘                             │
                     │ receive BYE / send BYE             │
              ┌──────▼──────┐                             │
              │   CLOSED    ├─────────────────────────────┘
              └─────────────┘
```

### State Definitions

| State | Description |
|---|---|
| IDLE | No session in progress |
| HELLO_SENT | Local HELLO sent; awaiting peer HELLO |
| KEY_EXCHANGE | Both HELLOs exchanged; awaiting KEY_EXCHANGE confirmation |
| ESTABLISHED | Session key established; DATA may flow |
| CLOSED | Session terminated; no further packets accepted |

---

## 7. Handshake Protocol

```
Alice (initiator)                        Bob (responder)
─────────────────                        ───────────────
Generate long-lived Ed25519 key pair     Generate long-lived Ed25519 key pair
Generate ephemeral X25519 key pair       Generate ephemeral X25519 key pair

── HELLO(Alice_ed25519_pub, Alice_x25519_pub) ──►
                                         Verify Alice's Ed25519 signature
                                         Record Alice's public keys
                                         Generate ephemeral X25519 key pair

◄── HELLO(Bob_ed25519_pub, Bob_x25519_pub) ──
Verify Bob's Ed25519 signature
Record Bob's public keys

Both sides independently compute:
  shared_secret = X25519(my_ephemeral_priv, peer_ephemeral_pub)
  session_key   = HKDF-SHA-256(shared_secret, info=…)
  mac_key       = HKDF-SHA-256(shared_secret, info=…)

── KEY_EXCHANGE(Encrypt("OK", session_key)) ──►
                                         Decrypt and verify "OK"

◄── KEY_EXCHANGE(Encrypt("OK", session_key)) ──
Decrypt and verify "OK"

        ══════════════ ESTABLISHED ══════════════

── DATA(Encrypt(plaintext, session_key)) ──►
◄── ACK ──
```

### 7.1 Security Properties of the Handshake

- **Mutual authentication**: both devices prove ownership of their Ed25519
  private keys by signing the HELLO packets.
- **Forward secrecy**: the session key is derived from ephemeral X25519 keys
  that are discarded after the exchange.  Compromise of Ed25519 identity keys
  after the session ends does not expose session content.
- **Key confirmation**: the KEY_EXCHANGE round confirms that both sides derived
  the same session key before any application data is sent.

---

## 8. Data Transfer

### 8.1 Ed25519 Path (Default)

DATA packets are signed with the sender's long-term Ed25519 identity key.
This provides a third-party-verifiable proof of origin but is computationally
expensive at high packet rates (~500 µs per signature on typical hardware).

### 8.2 HMAC-SHA-512 Fast Path (MAC_AUTH)

For established sessions, the MAC_AUTH flag enables an HMAC-SHA-512
authentication tag in place of the Ed25519 signature.  The HMAC is computed
over `signed_bytes()` (header + ciphertext) using the 64-byte MAC key.

Trade-offs:

| Property | Ed25519 | MAC_AUTH (HMAC-SHA-512) |
|---|---|---|
| Authentication | Third-party verifiable | Requires shared session key |
| Speed | ~500 µs/packet | ~10–40 µs/packet |
| Key material | Long-term identity key | Session-bound MAC key |
| Forward secrecy | No (identity key is long-lived) | Yes (session key) |

### 8.3 Replay Protection

Both paths are subject to the same replay protection:

1. **Timestamp check**: packet timestamp must be within ±30 000 ms of the
   receiver's clock.
2. **Sequence window**: a 64-entry sliding window of accepted sequence numbers
   rejects duplicate sequence numbers.

---

## 9. Trust Bootstrap Layer

### 9.1 Trust Levels

| Level | Value | How Established |
|---|---|---|
| UNKNOWN | 0 | Never seen |
| TOFU | 1 | Key accepted on first use |
| VERIFIED | 2 | Fingerprint confirmed out-of-band |
| ENDORSED | 3 | Vouched for by a VERIFIED peer |

Devices are rejected (UNKNOWN) unless `allow_tofu=True` is set or the key has
been pre-loaded at VERIFIED or higher.

### 9.2 Key Fingerprints

A fingerprint is the 64-hex-character SHA-256 digest of the Ed25519 public
key, formatted as sixteen colon-separated 4-character groups:

```
A1B2:C3D4:E5F6:0A1B:2C3D:4E5F:6A7B:8C9D:1E2F:3A4B:5C6D:7E8F:90AB:CDEF:0123:4567
```

Operators confirm fingerprints by phone, in person, or via another secure
channel, upgrading the device to VERIFIED.

### 9.3 QR Code Bootstrap

A device encodes its identity as a URL-safe string:

```
ZTLNP:1:<device_id_hex>:<ed25519_pub_hex>:<fingerprint_hex>
```

The receiver parses this string, verifies `fingerprint == SHA-256(ed25519_pub)`
and `device_id == SHA-256(ed25519_pub)`, then adds the key at VERIFIED level.

### 9.4 Web of Trust

An endorsement is a signed statement that a VERIFIED device vouches for
another:

```
body = [endorser_id(32)][target_id(32)][target_pub(32)]   # 96 bytes
blob = body + Ed25519_sign(endorser_priv, body)            # 160 bytes
```

**Depth limit**: endorsement chains are bounded by `max_endorsement_depth`
(default 3).  A device at depth _d_ may endorse others at depth _d+1_ only if
_d+1 ≤ max_endorsement_depth_.  This prevents unbounded trust amplification.

**Blacklisting**: any device may be explicitly distrusted (`distrust()`)
regardless of its stored trust record.

---

## 10. Identity Rotation

### 10.1 Motivation

A long-lived Ed25519 identity key is a single point of failure.  ZTLNP
supports forward-secure identity rotation: a device may replace its key while
preserving the trust relationships built up with the old key.

### 10.2 Key Transition Blob

```
[old_device_id   (32 B)]   SHA-256(old Ed25519 public key)
[new_device_id   (32 B)]   SHA-256(new Ed25519 public key)
[new_ed25519_pub (32 B)]   New Ed25519 public key (raw bytes)
[timestamp_ms    ( 8 B)]   Unix milliseconds (big-endian uint64)
[old_key_sig     (64 B)]   Ed25519 signature of the 104-byte body above
```

### 10.3 Receiver Validation

A receiver MUST verify:

1. `old_device_id` is known and trusted.
2. `new_device_id == SHA-256(new_ed25519_public)`.
3. `old_key_sig` verifies against the stored old public key.
4. `timestamp_ms ≤ local_clock + 30_000 ms` (not unreasonably in the future).
5. `timestamp_ms > last_rotation_timestamp` for this device (replay prevention).
6. The rotation count for this identity chain is below `max_rotations`.

On success, the receiver:

- Adds the new key at the same trust level as the old key.
- Retains the old key's endorser list on the new record.
- Records the old key as retired.

### 10.4 Sybil Limitation

A device is limited to `max_rotations` (default 10) rotations per identity
chain.  Once exhausted, a fresh VERIFIED endorsement from an existing VERIFIED
peer is required.

---

## 11. Mesh Routing

### 11.1 Route Entries

A route entry records:

- `device_id`: 32-byte destination identity.
- `transport`: the transport-layer object to use for forwarding.
- `next_hop_addr`: transport-level address of the next hop.
- `hop_count`: number of hops to destination (1 = directly reachable).
- `trust_score`: float in [0.0, 1.0].
- `latency_ms`: estimated round-trip latency.

### 11.2 Route Selection

Best route = highest score:

```
score = trust_score / (hop_count × max(latency_ms, 1))
```

Routes not refreshed within the stale-after period (default 300 s) are
excluded.

### 11.3 Route Announcements

ROUTE_ANNOUNCE packets flood reachability information.  Trust decays 10% per
hop:

```
path_trust = sender_trust × 0.9^hop_count
```

**Trust cap**: the router enforces `max_advertised_trust` (default 0.95).
No peer announcement can contribute more than this score regardless of its
claimed trust, defending against trust-inflation attacks.

### 11.4 Forwarding Transparency

A forwarding device transmits the raw packet bytes without modification.  The
final recipient verifies the **original sender's** signature, not the
forwarder's.

---

## 12. Reliable Delivery

### 12.1 Stop-and-Wait ARQ

`ReliableChannel` provides simple reliable delivery:

- One unacknowledged packet at a time.
- Exponential backoff: timeout doubles on each retry.
- `RetransmitError` after `max_retries` attempts.

Throughput: `payload_size / RTT`.

### 12.2 Sliding-Window ARQ

`SlidingWindowChannel` provides high-throughput reliable delivery:

- Up to `window_size` (default 64) packets in flight simultaneously.
- Selective ACK (SACK): receiver reports cumulative and out-of-order ranges.
- Sender retransmits only missing packets (not all unacked ones).
- Throughput: `window_size × payload_size / RTT`.

---

## 13. Traffic Analysis Resistance

### 13.1 Payload Padding

Padding is appended to the **plaintext** before encryption.  The last byte of
the padded plaintext encodes the pad length, allowing deterministic removal
after decryption.

```
padded = plaintext + random_bytes(pad_len) + byte(pad_len)
```

Supported strategies: FIXED (to a specific size), BLOCK (to a block boundary),
RANDOM (random 0–255 bytes), NONE.

The PADDING flag in the packet header signals that stripping is required.

### 13.2 Timing Jitter

A random delay drawn from `[0, max_jitter_ms)` can be injected before each
send operation to break timing correlations between application events and
observed packet arrivals.

### 13.3 Cover Traffic

`CoverTraffic` generates dummy DATA packets containing random ciphertext when
no real application data has been sent within the configured interval.  Cover
packets are indistinguishable from real data to an observer.

---

## 14. Security Considerations

### 14.1 Long-Term Key Compromise

If an Ed25519 private key is compromised after sessions have completed, the
session keys are **not** exposed (forward secrecy via X25519).  However, the
attacker can sign future HELLO packets impersonating the device.

**Mitigation**: rotate the key immediately using KEY_ROTATE and distribute the
signed transition blob to all peers.  The rotation budget limit (Section 10.4)
prevents an attacker from exhausting rotations to lock out the legitimate
device.

### 14.2 Man-in-the-Middle on First Contact

TOFU is vulnerable to MITM at first contact.  An active attacker can intercept
a HELLO and substitute their own public key.

**Mitigation**: confirm fingerprints out-of-band (phone, QR code, in person)
before trusting any device at VERIFIED level for sensitive operations.

### 14.3 Replay Attacks

The 30-second timestamp window and 64-entry sequence-number replay window
limit replay attacks to packets captured within that window.

**Residual risk**: an attacker who can delay packets by up to 30 seconds and
keep sequence numbers within the replay window can inject replayed packets.
Applications requiring stronger guarantees should implement application-level
nonces.

### 14.4 Route Poisoning

A malicious node can advertise inflated trust scores or fake destinations.

**Mitigations**:
- Trust cap (`max_advertised_trust`) limits per-hop score inflation.
- 10% per-hop decay penalises multi-hop paths claimed as highly trusted.
- `distrust()` blacklists confirmed malicious nodes.
- Endorsement depth limit prevents chain amplification.

### 14.5 Traffic Analysis

Despite encryption, an adversary can observe packet timing, size, and
frequency patterns.

**Mitigations**: padding (Section 13.1), timing jitter (Section 13.2), and
cover traffic (Section 13.3).  Full traffic analysis resistance requires
deployment of all three mechanisms simultaneously with carefully sized
parameters.

### 14.6 Cryptographic Algorithm Agility

The current specification mandates specific algorithm choices.  A future
version SHOULD define a negotiation mechanism to allow algorithm upgrades
without breaking compatibility.

---

## 15. Threat Model

### 15.1 Attacker Capabilities Assumed

| Capability | In Scope |
|---|---|
| Passive eavesdropping on the LAN | ✓ |
| Packet injection on the LAN | ✓ |
| Replay of previously captured packets | ✓ |
| Delay of packets (up to 30 s) | ✓ |
| Participation as a legitimate TOFU device | ✓ |
| Compromise of one device's private key | ✓ (limited impact by design) |
| Traffic analysis (timing, sizes) | ✓ (partially mitigated) |
| Global active MITM | ✓ (requires out-of-band verification) |

### 15.2 Attacker Capabilities NOT Assumed

| Capability | Out of Scope |
|---|---|
| Breaking Ed25519, X25519, AES-256-GCM, or HMAC-SHA-512 | ✗ |
| Compromising both sides of a session simultaneously | ✗ |
| Controlling the system clock of a legitimate device (beyond NTP drift) | ✗ |

---

## 16. Formal Security Properties

The following properties are claimed informally.  A formal proof would require
a symbolic model checker (e.g. ProVerif, Tamarin) operating on the protocol
steps defined in Section 7.

### 16.1 Authentication

**Claim**: A packet accepted by a receiver with `is_trusted(sender_id)=True`
was produced by the device that holds the Ed25519 private key corresponding to
`sender_id`, or by a device that holds the session's MAC key (if MAC_AUTH).

**Argument**: Ed25519 signatures are existentially unforgeable under chosen-
message attack (EU-CMA).  An attacker without the private key cannot produce a
valid signature.  The MAC key is derived from an X25519 exchange; an attacker
without the X25519 private key cannot derive the MAC key.

### 16.2 Confidentiality

**Claim**: The plaintext of a DATA packet is accessible only to the two
devices that share the session key.

**Argument**: AES-256-GCM is an authenticated encryption scheme.  An attacker
cannot decrypt ciphertext without the session key.  The session key is derived
from an X25519 shared secret that is computationally infeasible to obtain
without either party's ephemeral private key.

### 16.3 Integrity

**Claim**: Any modification of a packet in transit will be detected.

**Argument**: AES-256-GCM provides ciphertext integrity.  The Ed25519
signature (or HMAC-SHA-512 tag) additionally authenticates the unencrypted
header fields.

### 16.4 Replay Prevention

**Claim**: No packet can be replayed beyond the 30-second timestamp window or
the 64-entry sequence-number window.

**Argument**: The receiver rejects packets with timestamps outside the window
and maintains a set of recently seen sequence numbers.

### 16.5 Forward Secrecy

**Claim**: Compromise of an Ed25519 identity key does not expose the content
of past sessions.

**Argument**: Session keys are derived from ephemeral X25519 key pairs that
are discarded after the handshake.  The Ed25519 key is not used in the session
key derivation.

### 16.6 Identity Chain Integrity (Rotation)

**Claim**: A key transition accepted by a `RotationManager` was signed by the
device that held the old identity key, and the new identity corresponds to the
supplied public key.

**Argument**: The transition body includes both device IDs and the new public
key.  The signature is verified against the stored old key.  The replay check
ensures each transition is accepted exactly once.

---

## 17. IANA Considerations

This document currently makes no request of IANA.

If ZTLNP is submitted to the IETF for standardisation, the following
registries would be sought:

- A new "ZTLNP Packet Types" sub-registry (Section 5).
- A new "ZTLNP Packet Flags" sub-registry (Section 4.1).
- A new "ZTLNP Trust Levels" sub-registry (Section 9.1).
- An assigned UDP port number for `UdpTransport`.

---

## 18. References

### 18.1 Normative References

```
[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
           Requirement Levels", BCP 14, RFC 2119, March 1997.

[RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in
           RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.

[RFC7748]  Langley, A., Hamburg, M., and S. Turner, "Elliptic Curves
           for Security", RFC 7748, January 2016.
           (X25519 / Curve25519)

[RFC8032]  Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital
           Signature Algorithm (EdDSA)", RFC 8032, January 2017.
           (Ed25519)

[RFC5869]  Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand
           Key Derivation Function (HKDF)", RFC 5869, May 2010.

[NIST-GCM] Dworkin, M., "Recommendation for Block Cipher Modes of
           Operation: Galois/Counter Mode (GCM) and GMAC",
           NIST Special Publication 800-38D, November 2007.

[RFC2104]  Krawczyk, H., Bellare, M., and R. Canetti, "HMAC:
           Keyed-Hashing for Message Authentication",
           RFC 2104, February 1997.
```

### 18.2 Informative References

```
[WireGuard] Donenfeld, J., "WireGuard: Next Generation Kernel Network
            Tunnel", NDSS 2017.

[ZeroTrust] Rose, S. et al., "Zero Trust Architecture",
            NIST SP 800-207, August 2020.

[ProVerif]  Blanchet, B., "Proverif: Cryptographic Protocol Verifier
            in the Formal Model", https://proverif.inria.fr/

[Tamarin]   Basin, D. et al., "The TAMARIN Prover for the Symbolic
            Analysis of Security Protocols", CAV 2013.

[RFC6347]   Rescorla, E. and N. Modadugu, "Datagram Transport Layer
            Security Version 1.2", RFC 6347, January 2012.

[RFC9000]   Iyengar, J. and M. Thomson, "QUIC: A UDP-Based Multiplexed
            and Secure Transport", RFC 9000, May 2021.

[RFC2018]   Mathis, M. et al., "TCP Selective Acknowledgment Options",
            RFC 2018, October 1996.
```

---

## Appendix A: Test Vectors

### A.1 HKDF Key Derivation

The following vectors allow cross-implementation compatibility testing.
All values are hex-encoded.

```
IKM (X25519 shared secret, 32 B):
  000102030405060708090a0b0c0d0e0f
  101112131415161718191a1b1c1d1e1f

initiator_id (32 B):
  a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
  b0b1b2b3b4b5b6b7b8b9babbbcbdbebf

responder_id (32 B):
  c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
  d0d1d2d3d4d5d6d7d8d9dadbdcdddedf

session_key = HKDF-SHA-256(IKM, salt="", info=b"ZTLNP-v1-session-key" + initiator_id + responder_id, L=32)
  [to be computed and published in a future revision]

mac_key = HKDF-SHA-256(IKM, salt="", info=b"ZTLNP-v1-mac-key" + initiator_id + responder_id, L=64)
  [to be computed and published in a future revision]
```

> **Note**: Full test vectors (HELLO exchange, key derivation, DATA packet
> encode/decode, signature verification) will be added in revision 02 when
> a second independent implementation is available for cross-testing.

---

## Appendix B: Known Limitations

1. **No algorithm negotiation**: all implementations MUST use the exact
   algorithms specified in Section 3.  A future version SHOULD define a
   cipher-suite negotiation sub-protocol.
2. **No multi-party sessions**: sessions are strictly pairwise.  Group
   key agreement (e.g. for multicast) is out of scope for this version.
3. **32-bit sequence numbers**: wrap-around occurs after ~4 billion packets
   per session.  Long-lived sessions SHOULD initiate re-keying before
   approaching this limit.
4. **Padding overhead**: the 255-byte maximum padding per packet means that
   payloads larger than 255 bytes above the target MTU cannot be fixed-padded
   using a single padding segment.  Callers SHOULD size MTU budgets
   accordingly.
5. **Cover traffic at scale**: cover traffic is only effective when all peers
   participate.  Selective deployment reveals which devices have it enabled.
6. **No built-in PKI**: ZTLNP relies on out-of-band channels (QR, phone) for
   initial key verification.  A PKI or certificate-transparency integration
   would reduce the operator burden for large deployments.
7. **No fragmentation**: ZTLNP does not fragment packets larger than the
   transport MTU.  Applications are responsible for payload segmentation.

---

## Appendix C: Change Log

| Revision | Date | Changes |
|----------|------|---------|
| 00 | 2025-Q4 | Initial internal draft — core handshake, wire format, state machine |
| 01 | 2026-04 | Added trust bootstrap (TOFU/QR/web-of-trust), transport abstraction, mesh routing, stop-and-wait ARQ, MAC optimization (v2 features); added identity rotation, sliding-window ARQ + SACK, traffic analysis resistance (v3 features); reformatted as Draft RFC with Status of This Memo, Requirements Language, IANA Considerations, References |

---

*End of Specification*
