# ZTLNP Security Analysis

**Document status:** Draft  
**Revision:** 01  
**Date:** April 2026  
**Applies to:** ZTLNP v1 ([SPEC.md](../SPEC.md))  
**See also:** [Threat Model](threat-model.md) · [Performance Benchmarks](performance-benchmarks.md)

---

## Abstract

This document provides a structured security analysis of the Zero Trust Local
Network Protocol (ZTLNP).  It covers the security goals and trust assumptions
of the protocol, analyses the cryptographic construction of each security
property, compares ZTLNP's security model to related protocols (WireGuard,
DTLS, TLS 1.3, and ZeroTier), and identifies open questions suitable for
formal verification.

---

## 1. Security Goals

ZTLNP is designed to achieve the following security properties:

| Goal | Definition |
|------|-----------|
| **Mutual authentication** | Both communicating parties prove ownership of their Ed25519 identity keys before data is exchanged |
| **Payload confidentiality** | Application data is accessible only to the two parties sharing the session key |
| **Payload integrity** | Any modification to a packet in transit is detected and the packet is rejected |
| **Replay prevention** | No captured packet can be successfully re-delivered beyond a bounded time window |
| **Forward secrecy** | Compromise of long-term identity keys does not expose the content of past sessions |
| **Identity binding** | A device's identity is a cryptographic public key hash; no network topology fact (IP, MAC) confers identity |
| **Trust bootstrapping** | A well-defined path from zero knowledge to mutual VERIFIED trust, without requiring a PKI |
| **Key rotation** | A device can replace its identity key while preserving the trust built up with the old key |
| **Traffic analysis resistance** | Optional mechanisms limit what an observer can infer from packet metadata |

---

## 2. Trust Model and Assumptions

### 2.1 Trusted Components

The security of ZTLNP rests on the following assumptions:

1. **Cryptographic primitives are sound**: Ed25519, X25519, AES-256-GCM,
   HMAC-SHA-512, and HKDF-SHA-256 provide the security properties attributed
   to them by their designers and by NIST/IETF standards.

2. **Random number generation is secure**: the OS CSPRNG (used for key
   generation and nonce generation) produces unpredictable output.

3. **Honest parties' operating systems are trusted**: the OS does not leak
   key material to other processes.  ZTLNP does not attempt to defend against
   a compromised OS.

4. **Out-of-band channels for verification are authentic**: when a user
   confirms a fingerprint by phone or QR code, that channel is assumed to be
   authentic (i.e. the attacker cannot simultaneously intercept the ZTLNP
   channel and the voice/QR channel).

### 2.2 Untrusted Components

ZTLNP explicitly does **not** trust:

- The network medium (LAN, WLAN, or any transport)
- IP or MAC addresses
- Routing infrastructure
- Any device not explicitly enrolled in the local trust store
- Clock accuracy beyond ±30 seconds

---

## 3. Cryptographic Construction Analysis

### 3.1 Handshake Security

#### 3.1.1 Key Exchange

ZTLNP uses an authenticated Diffie-Hellman pattern:

```
Alice                                  Bob
──────                                 ───
Generate ephemeral (e_A_priv, e_A_pub) Generate ephemeral (e_B_priv, e_B_pub)
HELLO = sign(identity_A_priv, header + [id_A_pub, e_A_pub])
                  ──── HELLO_A ────►
                                       Verify signature under identity_A_pub
                                       HELLO = sign(identity_B_priv, header + [id_B_pub, e_B_pub])
                  ◄──── HELLO_B ────
Verify signature under identity_B_pub

Both compute:
  shared = X25519(e_A_priv, e_B_pub) = X25519(e_B_priv, e_A_pub)
  session_key = HKDF(shared, info = "ZTLNP-v1-session-key" + id_A + id_B)
  mac_key     = HKDF(shared, info = "ZTLNP-v1-mac-key" + id_A + id_B)
```

**Authentication analysis:**
- HELLO packets are signed with long-term Ed25519 identity keys.
- Ed25519 is existentially unforgeable under chosen-message attack (EU-CMA)
  under the hardness of the discrete-logarithm problem on the Edwards-curve
  Ed25519.
- An attacker cannot produce a valid HELLO on behalf of Alice without her
  Ed25519 private key.

**Forward secrecy analysis:**
- Session keys are derived entirely from ephemeral X25519 key material.
- The HKDF `info` string binds the derived key to the specific pair of device
  IDs, preventing key material from being used across different sessions.
- After the handshake, ephemeral private keys are discarded.
- Subsequent compromise of either Ed25519 identity key reveals no session key.

**Key confirmation:**
- The KEY_EXCHANGE round (both sides encrypt "OK" with the session key and
  verify the peer's ciphertext) confirms that both sides derived identical
  session keys before any application data flows.

#### 3.1.2 Comparison to Sigma and NOISE

The ZTLNP handshake resembles the **Sigma** protocol family [Krawczyk 2003]
and shares properties with the Noise IK and XX patterns:

| Property | ZTLNP | Noise IK | Noise XX | WireGuard (Noise IKpsk2) |
|----------|-------|----------|----------|--------------------------|
| Mutual authentication | ✓ | ✓ | ✓ | ✓ |
| Forward secrecy | ✓ | ✓ | ✓ | ✓ |
| Identity hiding | ✗ | Partial | ✓ | ✓ (responder) |
| 0-RTT data | ✗ | ✗ | ✗ | ✓ (with PSK) |
| Key confirmation | ✓ | ✓ | ✓ | ✓ |

**Identity hiding** is the main property ZTLNP does not provide: HELLO
packets include the sender's Ed25519 public key in plaintext.  An observer
can link network activity to a device's public identity.  This is an
intentional design trade-off in favour of simplicity; identity hiding would
require an additional round trip or use of ephemeral identities.

### 3.2 Data Packet Security

#### 3.2.1 AES-256-GCM

AES-256-GCM is an authenticated encryption with associated data (AEAD) scheme.
It provides:

- **Confidentiality**: under the assumption that AES is a pseudorandom
  permutation, AES-GCM ciphertext is computationally indistinguishable from
  random.
- **Ciphertext integrity**: the 128-bit GCM authentication tag is unforgeable
  without the session key.  AES-GCM is IND-CCA2 secure.
- **Nonce uniqueness**: the 12-byte nonce is generated fresh for every packet
  using the OS CSPRNG.  Nonce reuse under the same key is catastrophic for
  AES-GCM (revealing the XOR of plaintexts).  The random-nonce approach
  tolerates up to 2^32 packets per session before the birthday bound becomes
  relevant (nonce collision probability > 2^-32).

#### 3.2.2 Ed25519 Per-Packet Signature

The signature over `signed_bytes()` (header + ciphertext) provides:

- **Packet authentication**: proves the sender holds the Ed25519 private key
  corresponding to the claimed Sender ID.
- **Header integrity**: covers all header fields including Sender ID, Recipient
  ID, Timestamp, Sequence Number, Flags, and Nonce.
- **Third-party verifiability (non-repudiation)**: any party with the sender's
  public key can verify past signatures without the sender's participation.

#### 3.2.3 HMAC-SHA-512 Fast Path (MAC_AUTH)

For established sessions, MAC_AUTH replaces the Ed25519 signature with an
HMAC-SHA-512 tag:

**Security properties retained:**
- Packet authentication (requires shared MAC key)
- Header integrity (same `signed_bytes()` coverage)
- Replay protection (timestamp + sequence window)

**Security properties lost:**
- **Non-repudiation**: HMAC is symmetric; both parties share the MAC key.
  Either party could have generated any tag.
- **Third-party verifiability**: a third party without the session MAC key
  cannot verify MAC_AUTH packet authenticity.

**Key independence:** The MAC key is derived from the same X25519 shared
secret as the session key, but with a different HKDF `info` string
(`ZTLNP-v1-mac-key` vs `ZTLNP-v1-session-key`).  This cryptographic domain
separation ensures the two keys are computationally independent:

```
session_key = HKDF(shared, info = "ZTLNP-v1-session-key" + id_A + id_B, L=32)
mac_key     = HKDF(shared, info = "ZTLNP-v1-mac-key"     + id_A + id_B, L=64)
```

Given the pseudorandomness of HKDF output, knowing `session_key` reveals
nothing about `mac_key` and vice versa.

### 3.3 Replay Protection

The two-layer replay protection (timestamp + sequence window) provides:

**Timestamp bound (30 seconds):**
- Prevents replaying packets captured more than 30 seconds ago.
- Residual: an attacker can delay a fresh packet by up to 30 s.

**Sequence number window (64 entries):**
- Rejects duplicate sequence numbers within the window.
- Prevents packet duplication even within the 30-second window.
- Residual: an attacker can replay a packet if they can keep the sequence
  number within the current window AND deliver it within 30 seconds.

**Combined guarantee:** a packet can be replayed at most once, within 30
seconds of original transmission, if the sequence number falls within the
replay window.

### 3.4 Trust Bootstrap Security

#### 3.4.1 TOFU Analysis

Trust-on-first-use is vulnerable to an active MITM at first contact.  The
attacker intercepts HELLO_A and substitutes their own public key before Bob
sees it.  ZTLNP mitigates this by:

1. Labelling TOFU entries explicitly at the lowest trust level.
2. Providing fingerprint verification as the standard upgrade path.
3. Making fingerprints short enough to verify verbally (79 hex characters,
   formatted as 16 colon-separated groups).

#### 3.4.2 Web-of-Trust Security

The endorsement scheme provides:

- **Binding**: the endorsement body includes `endorser_id`, `target_id`, and
  `target_pub`.  A verifier who already trusts the endorser can confirm all
  three fields are consistent.
- **Unforgeability**: the 64-byte Ed25519 signature over the 96-byte body
  cannot be forged without the endorser's private key.
- **Depth limit**: without a depth limit, a compromised TOFU device could
  endorse another device, which endorses another, creating unlimited trust
  amplification.  The default limit of 3 ensures at most 3 hops from a
  VERIFIED anchor.

#### 3.4.3 Key Rotation Security

Key rotation security rests on:

1. The transition blob is signed by the **retiring** key, not the new one.
   This proves the legitimate key owner initiated the rotation.
2. The receiver verifies `new_device_id == SHA-256(new_ed25519_public)`,
   preventing device ID spoofing.
3. A strictly increasing timestamp requirement prevents replay of old
   transitions.
4. A rotation count limit prevents Sybil amplification.

The security of the rotation scheme depends on the retiring private key not
being compromised **before** the rotation is distributed.  If an attacker
holds the old key and the legitimate owner simultaneously attempts to rotate,
the attacker could issue their own transition first.  Peers that receive the
legitimate transition later would need to decide between the two competing
rotations — a race condition that ZTLNP v1 does not resolve.  This is noted
as a known limitation and area for future work.

---

## 4. Comparison to Related Protocols

### 4.1 WireGuard

WireGuard [Donenfeld 2017] is the closest published protocol to ZTLNP in its
cryptographic construction.

| Property | ZTLNP | WireGuard |
|----------|-------|-----------|
| Handshake pattern | Sigma-like (4-message) | Noise IKpsk2 (1.5-RTT) |
| Identity key | Ed25519 | Curve25519 (used directly) |
| Ephemeral key | X25519 | X25519 |
| Session key derivation | HKDF-SHA-256 | BLAKE2s |
| Payload encryption | AES-256-GCM | ChaCha20-Poly1305 |
| Per-packet authentication | Ed25519 or HMAC-SHA-512 | ChaCha20-Poly1305 tag only |
| Key agreement | X25519 DH | X25519 DH + static PSK |
| Forward secrecy | ✓ | ✓ |
| 0-RTT | ✗ | ✓ (with PSK ratchet) |
| Identity hiding | ✗ | ✓ (responder hidden) |
| First-contact model | TOFU / QR / WoT | Manual config only |
| Transport agnostic | ✓ | ✗ (UDP only) |
| Mesh routing | ✓ | ✗ (VPN overlay, not mesh) |
| Formal verification | Partial (ProVerif) | Full (ProVerif) |
| Standardisation | Draft (this document) | RFC 9000 aligned, not formally an RFC |

**Summary:** WireGuard has a more minimal cryptographic construction
(Noise protocol framework, formally verified), while ZTLNP adds richer
identity management, transport abstraction, and mesh routing at the cost
of a more complex handshake.  ZTLNP is better suited to ad-hoc local
networks where a trust bootstrap mechanism is needed; WireGuard is better
suited to pre-configured VPN tunnels.

### 4.2 DTLS 1.2 / 1.3

DTLS [RFC 6347] extends TLS to unreliable datagram transports.

| Property | ZTLNP | DTLS 1.3 |
|----------|-------|----------|
| Identity model | Cryptographic key hash | X.509 certificate + PKI |
| First-contact model | TOFU / fingerprint / QR | Requires certificate chain |
| Transport | Any | UDP only |
| Handshake | 4-message custom | TLS 1.3 handshake (2-RTT) |
| Session key | HKDF-SHA-256 | HKDF-SHA-256 |
| Per-packet auth | Ed25519 or HMAC | Record MAC (AEAD) |
| Forward secrecy | ✓ | ✓ (ECDHE) |
| Algorithm agility | ✗ (v1 fixed) | ✓ (cipher suites) |
| Mesh routing | ✓ | ✗ |
| Maturity | Draft | RFC 9147 |

**Summary:** DTLS requires a PKI or pre-shared certificates, which adds
deployment complexity.  ZTLNP's TOFU+fingerprint model is more suitable
for peer-to-peer device networks without a certificate authority.

### 4.3 TLS 1.3

TLS 1.3 [RFC 8446] is the dominant application-layer security protocol
for client-server communication.

| Property | ZTLNP | TLS 1.3 |
|----------|-------|---------|
| Target topology | Peer-to-peer mesh | Client-server |
| Identity model | Public key hash | X.509 + CA hierarchy |
| 0-RTT resumption | ✗ | ✓ (with replay risk) |
| Per-packet auth | Ed25519 per packet (optional) | AEAD record MAC only |
| Algorithm agility | ✗ (v1) | ✓ (negotiated) |
| Formal verification | Partial | Extensive (Tamarin, miTLS, etc.) |
| Transport | Any | TCP (typically) |

**Summary:** TLS 1.3 is unsuitable for local peer-to-peer mesh networking
where devices have no common PKI.  ZTLNP fills this gap.

### 4.4 ZeroTrust Architecture (NIST SP 800-207)

NIST's Zero Trust Architecture [NIST 800-207] is a philosophy and framework,
not a protocol.  ZTLNP implements the core ZTA principle ("never trust, always
verify") at the network packet level:

| ZTA Principle | ZTLNP Implementation |
|--------------|---------------------|
| Verify explicitly | Ed25519 signature on every packet |
| Use least privilege access | Trust levels (UNKNOWN/TOFU/VERIFIED/ENDORSED) gate communication |
| Assume breach | No IP/MAC trust; all devices treated as potentially hostile by default |
| Continuous validation | Per-packet authentication (not just at session establishment) |

---

## 5. Formal Security Properties

### 5.1 Authentication

**Claim (P1):** If a receiver accepts a packet signed under Sender ID _D_,
then the packet was produced by the holder of the Ed25519 private key
corresponding to _D_, or by the holder of the session MAC key (MAC_AUTH path).

**Argument:** Ed25519 is EU-CMA secure under the hardness assumption of the
discrete-logarithm problem on the elliptic curve Edwards25519.  No polynomial-
time algorithm can forge a valid Ed25519 signature without the private key.
For MAC_AUTH, the security is that of HMAC-SHA-512 under the assumption that
SHA-512 is a secure hash function; the MAC key is computationally hidden from
an adversary who did not participate in the X25519 handshake.

### 5.2 Confidentiality

**Claim (P2):** The plaintext of a ZTLNP DATA packet is computationally
inaccessible to any party that does not hold the session key.

**Argument:** AES-256-GCM is IND-CCA2 secure under the assumption that AES is
a pseudorandom permutation.  The session key is derived from an X25519 shared
secret via HKDF-SHA-256; recovering the session key requires either breaking
X25519 (computing a discrete logarithm on Curve25519) or breaking HKDF (a
pseudorandom function based on HMAC-SHA-256).

### 5.3 Integrity

**Claim (P3):** Any modification to a ZTLNP packet (header or payload) is
detected with probability 1 − 2^-64 for AES-GCM tag forgery, and with
negligible probability for Ed25519/HMAC-SHA-512 signature forgery.

**Argument:** AES-256-GCM provides a 128-bit authentication tag; an attacker's
probability of producing a valid forgery without the key is 2^-128 per attempt.
The Ed25519 signature and HMAC-SHA-512 tag both cover the full `signed_bytes()`
(header + ciphertext), so header modification is also detected.

### 5.4 Forward Secrecy

**Claim (P4):** Compromise of Alice's Ed25519 identity key at time T does not
reveal the content of any ZTLNP sessions completed before time T.

**Argument:** Session keys are derived from ephemeral X25519 key pairs that
are discarded immediately after the handshake.  The Ed25519 key is used only
to sign HELLO packets (providing authentication); it is not fed into the
session key derivation function.  An adversary holding Alice's Ed25519 key
cannot compute `X25519(e_A_priv, e_B_pub)` without `e_A_priv`, which has been
deleted.

### 5.5 Key Separation

**Claim (P5):** The session key and MAC key, both derived from the same X25519
shared secret, are computationally independent.

**Argument:** HKDF with distinct `info` strings produces outputs that are
computationally independent when the underlying hash function (SHA-256) is
pseudorandom.  Specifically:

```
session_key = HKDF-SHA-256(IKM, info = "ZTLNP-v1-session-key" + id_A + id_B)
mac_key     = HKDF-SHA-256(IKM, info = "ZTLNP-v1-mac-key"     + id_A + id_B)
```

The different `info` strings ensure different PRF inputs, producing different
(and computationally unlinkable) outputs.

### 5.6 Properties Requiring Formal Proof

The following properties are stated as claims but have not been formally
verified in a symbolic or computational model.  They are targets for future
work:

| Property | Status | Recommended tool |
|----------|--------|-----------------|
| P1 — Authentication | Informal argument | ProVerif / Tamarin |
| P2 — Confidentiality | Informal argument | ProVerif |
| P4 — Forward secrecy | Informal argument | Tamarin (trace-based) |
| Rotation chain integrity | Not modelled | Tamarin |
| Trust endorsement binding | Not modelled | ProVerif |

---

## 6. Known Weaknesses and Mitigations

### 6.1 No Algorithm Agility

ZTLNP v1 mandates specific algorithm choices.  While all chosen algorithms
are currently believed to be secure, algorithm agility would allow upgrading
algorithms if a weakness is discovered without breaking backward compatibility.

**Mitigation plan (v2):** Define a one-byte cipher-suite field in the HELLO
payload, with the current fixed suite as suite 0x01.

### 6.2 No Identity Hiding

HELLO packets include the sender's Ed25519 public key (and thus device ID) in
plaintext.  A passive observer can link all traffic from a device to its public
identity.

**Mitigation plan:** Adopt a Noise XX-style handshake where the initiator's
identity is encrypted using the responder's public key.  This requires the
initiator to know the responder's public key in advance.

### 6.3 AES-GCM Nonce Safety

AES-GCM is catastrophically insecure if the same nonce is reused under the
same key.  ZTLNP uses random 12-byte nonces.  The birthday bound for a
2^-32 collision probability is 2^32 ≈ 4 billion packets per session.

For long-lived sessions with very high packet rates, this limit can be
approached.  Applications MUST trigger re-keying (a new handshake) before
this limit is reached.

**Mitigation:** Future revisions SHOULD specify a rekeying protocol triggered
when the sequence number approaches 2^31 or after a configurable time limit.

### 6.4 Race Condition in Key Rotation

If both the legitimate device and an attacker holding the compromised key
attempt to issue a KEY_ROTATE simultaneously, peers may receive the transitions
in different orders, leading to inconsistent trust state across the network.

**Mitigation plan:** Define a priority mechanism (e.g. highest timestamp wins,
or a tie-breaking rule based on new device ID) and specify peer notification
via a broadcast KEY_ROTATE to allow conflict resolution.

### 6.5 Replay Window Size

The 64-entry sequence number replay window may be too small for
high-throughput sliding-window sessions where many packets are in flight.
Out-of-window packets could be falsely rejected as replays.

**Mitigation plan:** Make the replay window size configurable, with a default
that scales with the configured ARQ window size.

### 6.6 Post-Quantum Readiness

All asymmetric operations in ZTLNP v1 (Ed25519, X25519) are vulnerable to
Shor's algorithm on a sufficiently powerful quantum computer.  Harvest-now-
decrypt-later attacks may retroactively compromise sessions recorded today.

**Mitigation plan:** Hybrid key exchange (X25519 + ML-KEM-768 per NIST FIPS
203) in v2, and hybrid signatures (Ed25519 + ML-DSA per NIST FIPS 204) in v3.

---

## 7. Implementation Security Guidance

The following requirements apply to any conformant ZTLNP implementation:

1. **Constant-time operations**: Ed25519 and X25519 implementations MUST use
   constant-time arithmetic to avoid timing side channels.  The `cryptography`
   library (OpenSSL backend) satisfies this for these operations.

2. **Secure key deletion**: ephemeral X25519 private keys MUST be securely
   erased from memory after the handshake.

3. **CSPRNG**: all random values (keys, nonces, jitter delays, padding bytes)
   MUST be drawn from a cryptographically secure random number generator.
   In Python, `os.urandom()` satisfies this requirement on all supported
   platforms.

4. **Signature verification before decryption**: implementations MUST verify
   the signature (or HMAC tag) before attempting AES-GCM decryption to avoid
   oracle attacks.  (The ZTLNP reference implementation does this correctly.)

5. **Strict parsing**: packet parsing MUST validate length fields and reject
   malformed packets before further processing.  Implementations MUST NOT
   process a packet beyond the point of first validation failure.

6. **Trust store persistence**: the trust store SHOULD be persisted to durable
   storage with integrity protection (e.g. file signed by the device's identity
   key) to survive device restarts without losing trust relationships.

---

## 8. Security Review Checklist

The following checklist can be used to assess a ZTLNP implementation:

- [ ] Ed25519 key generation uses CSPRNG
- [ ] X25519 ephemeral keys are generated fresh per handshake
- [ ] X25519 ephemeral private keys are securely erased after handshake
- [ ] HKDF is called with distinct info strings for session key and MAC key
- [ ] AES-GCM nonces are generated fresh (random) per packet
- [ ] Ed25519/HMAC signature is verified BEFORE AES-GCM decryption
- [ ] Timestamp check rejects packets outside ±30 s window
- [ ] Sequence number replay window rejects duplicates
- [ ] TOFU entries are flagged as unverified until fingerprint confirmed
- [ ] Endorsement depth limit is enforced
- [ ] Rotation count limit is enforced
- [ ] KEY_ROTATE replays are rejected (strictly increasing timestamp)
- [ ] Route trust caps are applied to incoming ROUTE_ANNOUNCE packets
- [ ] Malformed packets are rejected before signature verification where possible

---

## 9. Conclusion

ZTLNP v1 provides a strong cryptographic security foundation for zero-trust
local networking.  Its core design choices — Ed25519 identity keys, X25519
ephemeral DH for forward secrecy, AES-256-GCM for payload encryption, and
HKDF for key derivation — are well-established, standardised, and widely
implemented.

The protocol's main differentiators over existing solutions (WireGuard, DTLS)
are its explicit trust bootstrap layer, transport agnosticism, identity-based
mesh routing, and optional traffic analysis resistance mechanisms.  These
features come at the cost of a more complex handshake and the lack of formal
verification — gaps that are explicitly acknowledged and targeted for future
work.

The most significant open security questions are:

1. **Formal verification** of the handshake authentication and secrecy
   properties (target: ProVerif model in v2).
2. **Post-quantum migration** plan (target: hybrid KEM in v2, hybrid
   signatures in v3).
3. **Identity hiding** in the handshake (target: Noise XX variant in v2).
4. **Key rotation race condition** resolution (target: consensus mechanism
   in v2).

---

## References

```
[RFC7748]    Langley et al., "Elliptic Curves for Security", RFC 7748, 2016.
[RFC8032]    Josefsson and Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, 2017.
[RFC5869]    Krawczyk and Eronen, "HMAC-based HKDF", RFC 5869, 2010.
[RFC8446]    Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, 2018.
[RFC6347]    Rescorla and Modadugu, "Datagram TLS Version 1.2", RFC 6347, 2012.
[RFC9147]    Rescorla et al., "DTLS 1.3", RFC 9147, 2022.
[NIST-GCM]   Dworkin, "NIST SP 800-38D: GCM and GMAC", 2007.
[NIST-800-207] Rose et al., "Zero Trust Architecture", NIST SP 800-207, 2020.
[WireGuard]  Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel", NDSS 2017.
[Krawczyk03] Krawczyk, "SIGMA: The 'SIGn-and-MAc' Approach to Authenticated DH", CRYPTO 2003.
[ProVerif]   Blanchet, "ProVerif: Cryptographic Protocol Verifier in the Formal Model", 2001–present.
[Tamarin]    Basin et al., "The TAMARIN Prover for the Symbolic Analysis of Security Protocols", CAV 2013.
[FIPS203]    NIST, "Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)", FIPS 203, 2024.
[FIPS204]    NIST, "Module-Lattice-Based Digital Signature Standard (ML-DSA)", FIPS 204, 2024.
```

---

*End of Security Analysis*
