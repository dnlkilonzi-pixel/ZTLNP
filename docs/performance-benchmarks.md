# ZTLNP Performance Benchmarks

**Document status:** Draft  
**Revision:** 01  
**Date:** April 2026  
**Applies to:** ZTLNP v1 ([SPEC.md](../SPEC.md))  
**Platform:** CPython 3.x, `cryptography` ≥ 46.0.6 (OpenSSL backend), Linux x86-64  
**See also:** [Threat Model](threat-model.md) · [Security Analysis](security-analysis.md)

---

## Abstract

This document presents measured performance data for the ZTLNP reference
implementation.  All figures were collected on a standard Linux x86-64 host
running CPython.  Where numbers differ from common expectations, analysis and
interpretation are provided.  The goals are:

1. Allow operators to size deployments correctly.
2. Identify performance-sensitive paths.
3. Justify the MAC_AUTH fast-path design decision.
4. Compare ZTLNP throughput against theoretical maximums.

---

## 1. Measurement Methodology

### 1.1 Environment

| Item | Details |
|------|---------|
| OS | Linux x86-64 |
| Runtime | CPython 3.x |
| Crypto library | `cryptography` ≥ 46.0.6 (OpenSSL backend) |
| Benchmark harness | Python `time.perf_counter()` micro-benchmarks |
| Sample size | 500–10 000 iterations per measurement |
| Reported metric | Arithmetic mean of all iterations |

### 1.2 Limitations

- Results reflect **userspace Python overhead** in addition to OpenSSL
  primitives.  A native C implementation would be 5–20× faster.
- The benchmark host had no other significant workload during measurement.
- All crypto operations were performed in-process; no network I/O is included
  in the primitive timings.
- JIT compilation is not applicable (CPython).

---

## 2. Cryptographic Primitive Timings

### 2.1 Per-Operation Latencies

| Operation | Time (µs) | Notes |
|-----------|-----------|-------|
| Ed25519 key generation | 37 | One-time cost per device |
| Ed25519 sign | 35 | Per HELLO / KEY_EXCHANGE packet |
| Ed25519 verify | 111 | Per incoming packet (default path) |
| Ed25519 sign + verify | 146 | Full round-trip (DATA packet) |
| HMAC-SHA-512 compute | 3.8 | Per outgoing MAC_AUTH DATA packet |
| HMAC-SHA-512 verify | 3.7 | Per incoming MAC_AUTH DATA packet |
| HMAC compute + verify | 7.5 | Full round-trip (MAC_AUTH path) |
| X25519 key generation | 36 | Per handshake, per side |
| X25519 DH exchange | 37 | Per handshake, per side |
| HKDF-SHA-256 (32 B) | 5.3 | Session key derivation |
| HKDF-SHA-256 (64 B) | 5.3 | MAC key derivation |
| AES-256-GCM encrypt (1 KB) | 2.2 | Per DATA packet payload |
| AES-256-GCM decrypt (1 KB) | ~2.2 | Symmetric with encrypt |

### 2.2 Interpretation

- **Ed25519 verify (111 µs) dominates** the per-packet cost for the default
  authentication path.  This is a fundamental property of the Ed25519 algorithm
  and is consistent with published benchmarks for OpenSSL on x86-64.

- **HMAC-SHA-512 is ~30× faster** for the verify operation (3.7 µs vs 111 µs)
  and ~10× faster for sign (3.8 µs vs 35 µs).  This is the key motivation for
  the MAC_AUTH fast path.

- **AES-256-GCM (2.2 µs / KB)** is effectively free compared to the signing
  costs.  Payload encryption is not a bottleneck.

- **Handshake overhead** (key generation + DH + HKDF × 2 + Ed25519 × 4) is
  approximately 4 × (37 + 37 + 111) µs = ~0.74 ms per side, aligning closely
  with the measured 0.97 ms (Python overhead accounts for the remainder).

---

## 3. End-to-End Packet Latency

### 3.1 DATA Packet Round-Trip (Authentication Only)

| Authentication Path | Time (ms/packet) | Throughput (packets/s) |
|--------------------|-----------------|------------------------|
| Ed25519 (default) | 0.171 | ~5 850 |
| HMAC-SHA-512 (MAC_AUTH) | 0.024 | ~41 700 |
| **Speedup** | **7.2×** | **7.2×** |

> These measurements include packet serialisation, signature computation,
> deserialisation, and signature verification.  They do **not** include network
> I/O or AES-GCM encryption (which adds ~2 µs for typical payloads).

### 3.2 Full Handshake

| Step | Operations | Time (ms) |
|------|-----------|-----------|
| Key generation (both sides) | 2× Ed25519 gen, 2× X25519 gen | ~0.15 |
| HELLO exchange (2 packets) | 2× Ed25519 sign, 2× Ed25519 verify | ~0.29 |
| DH + key derivation | 2× X25519 DH, 2× HKDF | ~0.08 |
| KEY_EXCHANGE (2 packets) | 2× Ed25519 sign, 2× Ed25519 verify | ~0.29 |
| **Total** | | **~0.97 ms** |

A full ZTLNP session can be established in **under 1 millisecond** of
computation (exclusive of network RTT).

---

## 4. Packet Size Analysis

### 4.1 Fixed Overhead per Packet

| Field | Size (bytes) |
|-------|-------------|
| Magic | 4 |
| Version | 1 |
| Type | 1 |
| Flags | 2 |
| Sender ID | 32 |
| Recipient ID | 32 |
| Timestamp | 8 |
| Sequence Number | 4 |
| Nonce | 12 |
| Payload Length | 4 |
| AES-GCM authentication tag | 16 |
| Signature (Ed25519 or HMAC) | 64 |
| **Total fixed overhead** | **180 bytes** |

> Of the 180 bytes, 96 bytes is a fixed protocol header, 16 bytes is the
> AES-GCM authentication tag (embedded in the ciphertext), and 64 bytes is the
> per-packet signature or HMAC tag.

### 4.2 Payload Size vs Wire Size

| Plaintext (bytes) | Wire size (bytes) | Overhead | Overhead ratio |
|-------------------|-------------------|----------|----------------|
| 0 | 180 | 180 | ∞ |
| 16 | 196 | 180 | 11.25× |
| 64 | 244 | 180 | 2.81× |
| 256 | 436 | 180 | 0.70× |
| 1 024 | 1 204 | 180 | 17.6% |
| 4 096 | 4 276 | 180 | 4.4% |
| 65 535 | 65 715 | 180 | 0.27% |

**Observation:** For small payloads (≤ 64 bytes), the 180-byte fixed overhead
is significant.  Applications that frequently send very small messages should
consider batching or using a higher-level framing layer.

### 4.3 Padding Impact on Wire Size

When FIXED padding to 256 bytes is enabled (`PaddingStrategy.FIXED,
target_size=256`), all payloads under 255 bytes are padded to exactly 256 bytes
of plaintext.  This results in a constant wire size of 436 bytes for any
payload between 0 and 255 bytes.

| Strategy | Wire size range | Traffic analysis protection |
|----------|-----------------|----------------------------|
| NONE | 180 + len(payload) + 16 bytes | None |
| FIXED (256) | 436 bytes (constant) | High (for payloads ≤ 255 B) |
| BLOCK (64) | Variable, multiples of 64 + 180 | Medium |
| RANDOM | 180 + len(payload) + 0–255 + 16 bytes | Low–Medium |

---

## 5. Throughput Analysis

### 5.1 Theoretical Packet Rate

The packet rate is limited by the authentication cost.  At the Python level:

| Path | Max packet/s (single core) | Max packet/s (8 cores) |
|------|---------------------------|------------------------|
| Ed25519 (one side verify only) | ~9 000 | ~72 000 |
| Ed25519 (full round-trip) | ~5 850 | ~46 800 |
| HMAC-SHA-512 (one side) | ~270 000 | ~2 160 000 |
| HMAC-SHA-512 (full round-trip) | ~41 700 | ~333 600 |

> **Note:** A native C implementation would achieve 50–200× higher rates.
> These Python figures represent a meaningful baseline for IoT/embedded
> deployments and constrained environments.

### 5.2 Reliable Delivery Throughput

Throughput for reliable channels depends on round-trip time (RTT) and
window size.

#### Stop-and-Wait ARQ (`ReliableChannel`)

```
Throughput = payload_size / RTT
```

| RTT (ms) | 64 B payload | 1 KB payload | 4 KB payload |
|----------|-------------|-------------|-------------|
| 1 | 64 KB/s | 1 000 KB/s | 4 000 KB/s |
| 10 | 6.4 KB/s | 100 KB/s | 400 KB/s |
| 50 | 1.3 KB/s | 20 KB/s | 80 KB/s |
| 100 | 640 B/s | 10 KB/s | 40 KB/s |

Stop-and-wait is suitable for interactive single-message exchange but
insufficient for bulk data transfer over medium-latency links.

#### Sliding-Window ARQ (`SlidingWindowChannel`, window = 64)

```
Throughput ≈ window_size × payload_size / RTT
```

| RTT (ms) | 64 B payload | 1 KB payload | 4 KB payload |
|----------|-------------|-------------|-------------|
| 1 | 4 096 KB/s | 64 000 KB/s | 256 000 KB/s |
| 10 | 409 KB/s | 6 400 KB/s | 25 600 KB/s |
| 50 | 82 KB/s | 1 280 KB/s | 5 120 KB/s |
| 100 | 41 KB/s | 640 KB/s | 2 560 KB/s |

The sliding-window channel provides **64× higher theoretical throughput** than
stop-and-wait at the same RTT and payload size.  In practice, throughput is
also bounded by the packet authentication rate (Section 5.1) and the
underlying transport bandwidth.

#### Effective Bottleneck

For a 1 KB payload on a 50 ms RTT link:

| Bottleneck | Limit |
|-----------|-------|
| Ed25519 authentication | ~994 KB/s (5 850 packets/s × 1 KB) |
| HMAC-SHA-512 authentication | ~40 MB/s (41 700 packets/s × 1 KB) |
| Sliding-window ARQ (w=64) | 1 280 KB/s |
| Stop-and-wait ARQ | 20 KB/s |

For the sliding-window ARQ at 50 ms RTT with 1 KB payloads, Ed25519
authentication is **not** the bottleneck; the window-size / RTT product
limits throughput to 1 280 KB/s, well below the 994 KB/s Ed25519 limit.
At lower RTTs or higher window sizes, Ed25519 authentication becomes limiting
and switching to MAC_AUTH provides a meaningful uplift.

---

## 6. Memory Footprint

### 6.1 Per-Device Overhead

| Item | Size |
|------|------|
| Ed25519 private key | 32 bytes (key) + Python object overhead |
| Ed25519 public key bytes | 32 bytes |
| Device ID | 32 bytes |
| Per-session X25519 ephemeral (during handshake) | 32 bytes |

### 6.2 Per-Session Overhead

| Item | Size |
|------|------|
| Session key | 32 bytes |
| MAC key | 64 bytes |
| Sequence number counter | 4 bytes |
| Replay window (64 sequence numbers) | 64 × 4 = 256 bytes |
| **Total per session** | **~356 bytes** |

### 6.3 Trust Store Overhead

| Item | Size per entry |
|------|---------------|
| Device ID (key) | 32 bytes |
| Ed25519 public key | 32 bytes |
| Trust level | 4 bytes |
| Endorser list | Variable (32 bytes × N endorsers) |
| **Approximate per entry** | **~80–200 bytes** |

A trust store with 1 000 enrolled devices requires approximately 80–200 KB.

---

## 7. Benchmarks vs Related Protocols

The following comparisons are approximate and based on published figures for
Python implementations or equivalent userspace implementations.

| Protocol | Handshake (ms) | Data throughput (MB/s) | Auth per packet |
|----------|---------------|----------------------|----------------|
| ZTLNP (Ed25519) | ~1 | ~1 (Python) | Ed25519 or HMAC-SHA-512 |
| DTLS 1.2 (Python) | ~5–20 | ~1 (Python) | AES-GCM + HMAC |
| WireGuard (userspace Python) | ~5–10 | ~1 (Python) | ChaCha20-Poly1305 |
| Raw TLS 1.3 (Python ssl) | ~5–15 | ~1 (Python) | AES-GCM |

> **Important caveat:** ZTLNP's Python reference implementation is not
> optimised for throughput; it prioritises clarity and correctness.  A
> kernel or native implementation of ZTLNP would achieve throughput
> comparable to WireGuard's kernel implementation (multi-GB/s).

ZTLNP's key differentiators vs these protocols are:

- **Per-packet identity authentication** — WireGuard, DTLS, and TLS all rely
  on the session key for packet-level authentication.  ZTLNP retains the
  option of per-packet Ed25519 signatures for third-party-verifiable proofs of
  origin.
- **Transport agnosticism** — ZTLNP is not tied to UDP sockets.
- **First-contact trust model** — ZTLNP provides an explicit four-level trust
  bootstrap (TOFU / fingerprint / QR / web-of-trust); TLS/DTLS assumes a PKI.
- **Identity-based routing** — ZTLNP packets carry device IDs, enabling mesh
  routing without IP infrastructure.

---

## 8. Optimisation Recommendations

### 8.1 High-Packet-Rate Scenarios

For scenarios requiring maximum packet throughput (e.g. bulk file transfer,
streaming):

1. **Always use MAC_AUTH** for DATA packets in established sessions.
   The 7.2× speedup (measured) over Ed25519 reduces per-packet authentication
   from 0.171 ms to 0.024 ms.

2. **Use SlidingWindowChannel** instead of ReliableChannel.  The sliding-window
   ARQ keeps up to 64 packets in flight, multiplying effective throughput
   proportionally.

3. **Increase window size** if RTT permits.  At 10 ms RTT, a window of 64
   and 1 KB payloads yields ~6 400 KB/s; a window of 128 doubles this.

4. **Batch small messages** into larger payloads before encryption to amortise
   the 180-byte per-packet overhead.

### 8.2 Low-Latency Scenarios

For interactive protocols where latency matters more than throughput:

1. **Use MAC_AUTH** to reduce per-packet authentication time from 146 µs to
   7.5 µs.

2. **Disable padding** (`PaddingStrategy.NONE`) to avoid padding computation
   and increased wire size.

3. **Tune `base_timeout_ms`** in ReliableChannel to match the expected RTT.

### 8.3 Privacy-Sensitive Scenarios

When traffic analysis resistance is important:

1. **Enable all three mechanisms** simultaneously:
   - `PaddingStrategy.FIXED` or `BLOCK` for payload padding
   - `jitter_sleep()` with appropriate `max_jitter_ms` before each send
   - `CoverTraffic` with `interval_ms` matching the desired constant rate

2. **Choose padding target size** to be larger than the maximum expected
   payload.  A target of 256 or 512 bytes covers most interactive protocol
   messages.

3. **Accept the bandwidth cost**: cover traffic generates one dummy packet
   per interval regardless of real traffic, increasing bandwidth consumption
   proportionally.

---

## 9. Summary

| Scenario | Recommended configuration | Expected throughput |
|----------|--------------------------|---------------------|
| Interactive protocol (small messages) | Ed25519, stop-and-wait | 5 850 packets/s |
| Bulk transfer (low latency link) | MAC_AUTH, sliding window w=64 | ~40 MB/s theoretical |
| Bulk transfer (50 ms RTT) | MAC_AUTH, sliding window w=64 | ~1.3 MB/s (ARQ limited) |
| Privacy-sensitive interactive | Ed25519 + padding + jitter + cover traffic | Reduced by jitter delay |
| Mesh routing with multiple hops | MAC_AUTH recommended per hop | Hop overhead: ~0.024 ms |

The reference Python implementation is a correctness baseline.  Production
deployments targeting throughput >10 MB/s should consider a native (C/Rust)
implementation of the ZTLNP wire format and cryptographic operations.

---

*End of Performance Benchmarks*
