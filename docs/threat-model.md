# ZTLNP Threat Model

**Document status:** Draft  
**Revision:** 01  
**Date:** April 2026  
**Applies to:** ZTLNP v1 ([SPEC.md](../SPEC.md))  
**See also:** [Security Analysis](security-analysis.md) · [Performance Benchmarks](performance-benchmarks.md)

---

## Abstract

This document provides a structured threat model for the Zero Trust Local
Network Protocol (ZTLNP).  It identifies protected assets, characterises
attacker capabilities and objectives, enumerates concrete attack scenarios,
and describes the mitigations ZTLNP provides for each.  Residual risks and
deployment recommendations are included.

---

## 1. Scope and Methodology

The threat model covers a ZTLNP deployment over a shared local network segment
(LAN, WLAN, or any medium where an attacker can observe and inject traffic).
The analysis follows the Microsoft STRIDE methodology, supplemented by
attack-tree decomposition for the most critical threats.

### 1.1 STRIDE Summary

| Category | Description |
|----------|-------------|
| **S**poofing | Impersonating a legitimate device |
| **T**ampering | Modifying packets in transit |
| **R**epudiation | Denying the sending of a packet |
| **I**nformation disclosure | Reading encrypted traffic |
| **D**enial of service | Disrupting legitimate communication |
| **E**levation of privilege | Gaining trust above what was granted |

---

## 2. Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| **Device identity key** | Ed25519 private key uniquely identifying a device | Critical |
| **Session key** | 32-byte AES-256-GCM key for one session | High |
| **MAC key** | 64-byte HMAC-SHA-512 key for one session | High |
| **Application payload** | Plaintext data sent between devices | Depends on application |
| **Trust store** | Mapping of device IDs to trust levels and public keys | High |
| **Endorsement chain** | Web-of-trust endorsement blobs | Medium |
| **Traffic metadata** | Timing, size, and frequency of packets | Medium |
| **Device presence** | Whether a device is active on the network | Low–Medium |

---

## 3. Threat Actors

### 3.1 Passive Network Observer

**Profile:** An adversary who can read all packets on the LAN segment but
cannot inject or modify traffic.  Examples: network tap, compromised switch
port mirroring, WLAN eavesdropper.

**Capabilities:**
- Observe all ZTLNP packet bytes in transit
- Correlate timing and packet sizes
- Record traffic for offline analysis

**Objectives:**
- Recover plaintext application payloads
- Identify communicating device pairs
- Infer application behaviour from traffic patterns

### 3.2 Active Network Attacker

**Profile:** An adversary who can both read and inject (or modify) packets.
Examples: ARP poisoning, rogue WLAN AP, compromised router.

**Capabilities:** All capabilities of 3.1, plus:
- Inject arbitrary packets with any claimed source
- Modify packets in flight
- Drop, delay, or reorder packets
- Replay previously captured packets

**Objectives:** All objectives of 3.1, plus:
- Impersonate a legitimate device
- Inject false data
- Disrupt communication

### 3.3 Insider / Compromised Device

**Profile:** A device that is legitimately enrolled in the network but is now
under adversary control (e.g. malware, supply-chain compromise).

**Capabilities:** All capabilities of 3.2, plus:
- Sign packets with a valid enrolled key
- Participate in handshakes legitimately
- Read all traffic addressed to it

**Objectives:**
- Exfiltrate application data it receives
- Impersonate a higher-trust device it has not enrolled
- Spread to other devices via the trust network

### 3.4 Physical Attacker

**Profile:** An adversary with brief physical access to a device.

**Capabilities:**
- Read device storage (extract private key if unprotected at rest)
- Observe key material during operation if the OS is unprotected

**Objectives:**
- Extract Ed25519 or session key material
- Enroll a cloned device into the trust network

### 3.5 State-Level / Well-Resourced Attacker

**Capabilities:** All of the above, plus:
- Compromise NTP infrastructure (clock skew attacks)
- Mount side-channel attacks on cryptographic operations
- Cryptanalysis of weakened random number generators

---

## 4. Threat Analysis (STRIDE × Asset Matrix)

### 4.1 Spoofing

#### T1 — IP/MAC Address Spoofing

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing |
| **Asset** | Device identity |
| **Attacker** | Active network attacker |
| **Impact** | High |
| **Likelihood** | High (trivial on most LANs) |

**Attack:** Attacker sets their network interface to the MAC or IP address of
a legitimate device and sends packets appearing to originate from it.

**ZTLNP mitigation:** ZTLNP ignores IP and MAC addresses entirely.  Every
packet is authenticated by an Ed25519 signature over the ZTLNP header and
payload.  Without the target device's Ed25519 private key, the attacker cannot
produce a valid signature.  **Fully mitigated.**

---

#### T2 — First-Contact TOFU Interception (MITM)

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing, Elevation of privilege |
| **Asset** | Trust store |
| **Attacker** | Active network attacker |
| **Impact** | Critical |
| **Likelihood** | Medium (requires active interception at first contact) |

**Attack:** Alice sends a HELLO to Bob for the first time.  Attacker intercepts
and substitutes their own Ed25519 public key.  If Alice has TOFU enabled, she
accepts the attacker's key as "Bob".

**ZTLNP mitigation:** Partial.  TOFU is explicitly labelled as an untrusted
level.  Applications SHOULD prompt the user to verify the fingerprint before
performing sensitive operations.  QR-code and phone-call fingerprint
verification upgrade the record to VERIFIED, which fully mitigates the attack.
**Residual risk:** Deployments that leave devices at TOFU level indefinitely
remain vulnerable to this attack for those connections.

---

#### T3 — Stale Identity Impersonation After Key Compromise

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing |
| **Asset** | Device identity key |
| **Attacker** | Physical attacker or insider |
| **Impact** | High |
| **Likelihood** | Low (requires key exfiltration) |

**Attack:** Attacker extracts Alice's Ed25519 private key and uses it to sign
HELLO packets, impersonating Alice.

**ZTLNP mitigation:** Alice can issue a KEY_ROTATE packet signed with the
compromised key, nominating a new key.  Peers that accept the rotation will
treat the old key as retired.  The rotation count limit (default 10) prevents
the attacker from exhausting the rotation budget to lock out the legitimate
device.  **Partially mitigated**; requires timely key rotation and out-of-band
notification to peers who have not yet received the rotation.

---

### 4.2 Tampering

#### T4 — In-Transit Packet Modification

| Field | Value |
|-------|-------|
| **STRIDE** | Tampering |
| **Asset** | Application payload, packet integrity |
| **Attacker** | Active network attacker |
| **Impact** | High |
| **Likelihood** | High (trivial for an active attacker) |

**Attack:** Attacker flips bits in an encrypted DATA packet.

**ZTLNP mitigation:** AES-256-GCM is an authenticated encryption scheme.
Any modification to the ciphertext or the associated header (authenticated by
the Ed25519/HMAC-SHA-512 signature) causes decryption to fail with an
authentication error.  **Fully mitigated.**

---

#### T5 — Header Field Manipulation

| Field | Value |
|-------|-------|
| **STRIDE** | Tampering, Spoofing |
| **Asset** | Sender ID, Recipient ID, Timestamp |
| **Attacker** | Active network attacker |
| **Impact** | Medium |
| **Likelihood** | Medium |

**Attack:** Attacker modifies the Sender ID, Recipient ID, or Timestamp fields
in the fixed header.

**ZTLNP mitigation:** The Ed25519 signature (or HMAC-SHA-512 tag) covers
`signed_bytes()`, which includes the entire header and payload.  Any
modification to any header field invalidates the signature.  **Fully
mitigated.**

---

### 4.3 Repudiation

#### T6 — Denial of Sending a Packet

| Field | Value |
|-------|-------|
| **STRIDE** | Repudiation |
| **Asset** | Application payload, audit trail |
| **Attacker** | Insider / enrolled device |
| **Impact** | Medium |
| **Likelihood** | Medium |

**Attack:** A device claims it never sent a particular DATA packet.

**ZTLNP mitigation (Ed25519 path):** Ed25519 signatures are asymmetric.  Only
the holder of the private key can produce a valid signature.  A third party in
possession of the sender's Ed25519 public key can verify the signature without
the sender's cooperation.  This provides non-repudiation for the Ed25519 path.

**ZTLNP mitigation (MAC_AUTH path):** HMAC-SHA-512 is symmetric — any party
with the MAC key can compute the same tag.  Non-repudiation is **not** provided
for MAC_AUTH DATA packets; both sides share the MAC key.  Applications
requiring non-repudiation MUST use the Ed25519 path.

---

### 4.4 Information Disclosure

#### T7 — Passive Traffic Decryption

| Field | Value |
|-------|-------|
| **STRIDE** | Information disclosure |
| **Asset** | Application payload |
| **Attacker** | Passive observer |
| **Impact** | High |
| **Likelihood** | High (capturing packets is trivial) |

**Attack:** Attacker captures all ZTLNP packets and attempts to decrypt them.

**ZTLNP mitigation:** AES-256-GCM with 256-bit keys provides 128-bit security
against brute-force attacks.  The session key is derived from an X25519 shared
secret with HKDF-SHA-256; recovering it requires breaking X25519 or the
underlying Curve25519 discrete-logarithm problem.  **Fully mitigated** against
computationally bounded adversaries.

---

#### T8 — Session Key Recovery from Long-Term Key

| Field | Value |
|-------|-------|
| **STRIDE** | Information disclosure |
| **Asset** | Session key, application payload |
| **Attacker** | Physical attacker (future) |
| **Impact** | Critical (retroactive decryption of archived traffic) |
| **Likelihood** | Low (requires key exfiltration) |

**Attack:** Attacker compromises Alice's Ed25519 private key after sessions
have completed and attempts to recover session keys to decrypt archived traffic.

**ZTLNP mitigation:** Session keys are derived from **ephemeral** X25519 key
pairs that are discarded after the handshake.  The Ed25519 private key plays no
role in session key derivation.  Forward secrecy is provided.  **Fully
mitigated.**

---

#### T9 — Traffic Analysis

| Field | Value |
|-------|-------|
| **STRIDE** | Information disclosure |
| **Asset** | Traffic metadata |
| **Attacker** | Passive or active observer |
| **Impact** | Medium |
| **Likelihood** | High |

**Attack:** Even without decrypting payloads, the attacker observes:
- Which pairs of device IDs communicate
- Packet sizes (revealing message lengths)
- Timing (revealing application behaviour patterns, e.g. keystrokes)
- Silence intervals (revealing inactivity)

**ZTLNP mitigation:**
- **Payload padding** (FIXED/BLOCK/RANDOM strategies) normalises packet sizes.
- **Timing jitter** adds random delay before sends, breaking timing correlations.
- **Cover traffic** maintains a constant observed packet rate, eliminating silence periods.

**Residual risk:** All three mechanisms must be deployed simultaneously to be
effective.  Partial deployment (e.g. padding without cover traffic) is better
than nothing but still leaks some information.  The ZTLNP padding scheme is
limited to 255 bytes per packet; payloads requiring larger padding must be
split or padded with multiple segments.

---

### 4.5 Denial of Service

#### T10 — Replay Attack

| Field | Value |
|-------|-------|
| **STRIDE** | Denial of service, Tampering |
| **Asset** | Application correctness, replay protection |
| **Attacker** | Active network attacker |
| **Impact** | Medium |
| **Likelihood** | Medium |

**Attack:** Attacker captures a legitimate DATA packet and re-injects it later.
If the same packet is delivered to the application twice, it may cause incorrect
state.

**ZTLNP mitigation:**
1. **Timestamp window**: packets with timestamps outside ±30 seconds of the
   receiver's clock are rejected.
2. **Sequence window**: a 64-entry sliding window rejects duplicate or
   out-of-window sequence numbers.

**Residual risk:** An attacker who can delay a packet by up to 30 seconds and
ensure its sequence number falls within the window can successfully replay it.
Applications requiring stronger guarantees SHOULD implement application-layer
idempotency checks or nonces.

---

#### T11 — Resource Exhaustion (DoS via Forged Packets)

| Field | Value |
|-------|-------|
| **STRIDE** | Denial of service |
| **Asset** | CPU availability |
| **Attacker** | Active network attacker |
| **Impact** | Medium |
| **Likelihood** | High |

**Attack:** Attacker floods a device with forged ZTLNP packets.  Each packet
must be processed up to the point where the signature is rejected.

**ZTLNP mitigation:** Ed25519 verification is ~111 µs per packet (measured).
At 9000 forged packets/second, a single core would be fully occupied.  HMAC
verification is faster (~3.7 µs), but only applies to packets from established
sessions (the receiver can filter by known Sender ID before attempting HMAC
verification).

**Residual risk:** ZTLNP does not specify rate-limiting or connection-admission
control.  Implementations SHOULD add transport-level rate limiting (e.g.
per-source-address bucket) before signature verification to mitigate flood
attacks.

---

#### T12 — Route Poisoning

| Field | Value |
|-------|-------|
| **STRIDE** | Denial of service, Elevation of privilege |
| **Asset** | Routing table, trust store |
| **Attacker** | Insider / compromised device |
| **Impact** | Medium |
| **Likelihood** | Medium |

**Attack:** A malicious enrolled device sends ROUTE_ANNOUNCE packets
advertising inflated trust scores or claiming direct reachability to
destinations it cannot actually reach.

**ZTLNP mitigation:**
- `max_advertised_trust` cap (default 0.95) limits per-hop score inflation.
- 10% per-hop trust decay penalises longer claimed paths.
- Endorsement depth limit (default 3) caps trust amplification chains.
- `distrust()` blacklists confirmed malicious nodes.

**Residual risk:** Until a malicious node is identified and blacklisted,
it can influence route selection.  Monitoring for anomalous route
advertisements is recommended for high-security deployments.

---

### 4.6 Elevation of Privilege

#### T13 — Trust Level Escalation via Forged Endorsement

| Field | Value |
|-------|-------|
| **STRIDE** | Elevation of privilege |
| **Asset** | Trust store |
| **Attacker** | Insider / compromised TOFU device |
| **Impact** | High |
| **Likelihood** | Low |

**Attack:** Attacker at TOFU level attempts to forge a web-of-trust endorsement
blob to elevate itself to ENDORSED status.

**ZTLNP mitigation:** Endorsement blobs carry an Ed25519 signature from the
endorser.  The endorser's key must already be at VERIFIED level in the target
trust store.  The receiver verifies the endorser's signature before accepting
the endorsement.  Without the endorser's private key, forgery is infeasible.
**Fully mitigated.**

---

#### T14 — Sybil Attack via Unlimited Key Rotation

| Field | Value |
|-------|-------|
| **STRIDE** | Elevation of privilege |
| **Asset** | Trust store |
| **Attacker** | Insider / compromised device |
| **Impact** | Medium |
| **Likelihood** | Low |

**Attack:** An attacker repeatedly rotates their key, building a long chain of
keys each endorsed by the previous one, amplifying their apparent trust depth.

**ZTLNP mitigation:** The `RotationManager` enforces a `max_rotations` limit
(default 10) per identity chain.  Once exhausted, a fresh VERIFIED endorsement
from an external VERIFIED peer is required.  **Fully mitigated** within the
configured limit.

---

## 5. Attack Trees

### 5.1 "Read a protected DATA packet"

```
Goal: Recover plaintext of a ZTLNP DATA packet

OR ──┬── Break AES-256-GCM directly
     │     └── Infeasible (128-bit security)
     │
     ├── Recover session key
     │     OR ──┬── Recover X25519 ephemeral private key
     │          │     └── Solve ECDLP on Curve25519 — infeasible
     │          │
     │          └── Compromise device memory during/after handshake
     │                └── Physical/OS-level attack (out of scope)
     │
     └── Perform MITM during handshake (substitute X25519 keys)
           └── Alice/Bob must accept unverified (TOFU) key
                 └── Mitigated by fingerprint/QR verification
```

### 5.2 "Impersonate a device"

```
Goal: Send packets that are accepted as coming from a legitimate device

OR ──┬── Forge Ed25519 signature without private key
     │     └── Infeasible (EU-CMA security of Ed25519)
     │
     ├── Obtain the device's Ed25519 private key
     │     OR ──┬── Physical access to device storage
     │          └── OS/memory compromise
     │
     └── Perform TOFU MITM (only before fingerprint verification)
           └── Mitigated by fingerprint/QR verification
```

### 5.3 "Disrupt communication"

```
Goal: Prevent legitimate devices from communicating

OR ──┬── Drop packets in transit (transport-layer DoS)
     │     └── ZTLNP ARQ retransmits; persistent drop requires sustained attack
     │
     ├── Flood target with forged packets (signature verification DoS)
     │     └── Partially mitigated; implementations should rate-limit
     │
     └── Poison routing table with false ROUTE_ANNOUNCEs
           └── Mitigated by trust caps and blacklisting
```

---

## 6. Threat-Mitigation Matrix

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| T1 IP/MAC spoofing | Ed25519 per-packet authentication | None |
| T2 TOFU MITM | Fingerprint / QR verification | TOFU-level peers until verified |
| T3 Key compromise impersonation | KEY_ROTATE + peer notification | Window before rotation accepted |
| T4 In-transit modification | AES-256-GCM integrity | None |
| T5 Header manipulation | Ed25519/HMAC over full header | None |
| T6 Repudiation | Ed25519 non-repudiation (Ed25519 path) | MAC_AUTH path does not provide NR |
| T7 Passive decryption | AES-256-GCM + forward secrecy | None (computationally bounded) |
| T8 Retroactive decryption | Forward secrecy via X25519 ephemeral | None |
| T9 Traffic analysis | Padding + jitter + cover traffic | Partial; all three must be active |
| T10 Replay | Timestamp + sequence window | 30 s window; app-layer nonces recommended |
| T11 Packet flood DoS | Signature verification cost | Rate limiting needed at transport layer |
| T12 Route poisoning | Trust caps + decay + blacklist | Until malicious node identified |
| T13 Forged endorsement | Endorser Ed25519 signature check | None |
| T14 Sybil via rotation | max_rotations limit | Attacker can exhaust 10 rotations |

---

## 7. Deployment Recommendations

1. **Verify all TOFU entries** — never leave devices permanently at TOFU level.
   Use QR-code bootstrap or phone fingerprint confirmation within 24 hours of
   first contact.

2. **Enable cover traffic and padding together** — deploying padding without
   cover traffic still leaks silence patterns; enabling all three mechanisms
   (padding + jitter + cover traffic) provides meaningful traffic analysis
   resistance.

3. **Rotate keys proactively** — don't wait for a compromise event.  Rotate
   every device's identity key periodically (e.g. annually) to reduce the
   impact of silent, undetected key compromise.

4. **Implement transport-layer rate limiting** — add per-source-address rate
   limiting before ZTLNP signature verification to protect against packet flood
   DoS.

5. **Monitor for route poisoning** — alert on sudden changes in route trust
   scores or unusual ROUTE_ANNOUNCE patterns.

6. **Use the Ed25519 path for auditable operations** — when non-repudiation is
   required (e.g. commands, financial transactions) use the default Ed25519
   signature path, not MAC_AUTH.

7. **Protect private key storage** — encrypt private keys at rest using
   OS-provided keystores.  ZTLNP does not specify key storage; implementations
   SHOULD use hardware security modules or OS trust anchors.

---

## 8. Out-of-Scope Threats

The following threats are acknowledged but explicitly out of scope for ZTLNP v1:

| Threat | Reason out of scope |
|--------|---------------------|
| Breaking Ed25519, X25519, or AES-256-GCM | Assumed computationally infeasible |
| Compromising both sides of a session simultaneously | Session key then directly accessible |
| OS-level compromise of the device running ZTLNP | Protocol cannot defend against a compromised host |
| Side-channel attacks (timing, power) on crypto primitives | Delegated to the underlying `cryptography` library |
| Denial of service via transport-layer flooding | Must be handled at the transport / firewall layer |
| Quantum adversaries | Post-quantum migration is future work |

---

## 9. Future Work

- **Post-quantum readiness**: replace X25519 with a hybrid KEM (e.g.
  X25519+ML-KEM-768 per NIST FIPS 203) to resist harvest-now-decrypt-later
  attacks.
- **Formal verification**: model the ZTLNP handshake in ProVerif or Tamarin
  to obtain machine-verified authentication and secrecy proofs.
- **Hardware-backed keys**: specify integration with TPM, Secure Enclave, or
  FIDO2 hardware authenticators for identity key storage.
- **Group sessions**: extend the protocol to support multicast/group key
  agreement for mesh-broadcast use cases.

---

*End of Threat Model*
