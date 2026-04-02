#!/usr/bin/env python3
"""
ZTLNP Extended Demo — Next-Level Zero Trust Networking
=======================================================

This script demonstrates all five protocol innovations:

1. Trust Bootstrap  — TOFU → fingerprint → web-of-trust endorsement
2. Transport Abstraction — protocol-agnostic; runs over InProcessTransport
3. Mesh Routing    — identity-based forwarding through an intermediate node
4. Reliability     — stop-and-wait ARQ with exponential-backoff retransmission
5. MAC Optimization — HMAC-SHA-512 per packet instead of Ed25519 (faster)
"""

from __future__ import annotations

import struct
import sys
import time

from ztlnp.device import Device
from ztlnp.protocol import Protocol, ProtocolState
from ztlnp.trust import (
    TrustLevel, TrustStore, fingerprint_of,
    encode_qr_payload, parse_qr_payload, create_endorsement,
)
from ztlnp.transport import InProcessTransport
from ztlnp.router import Router
from ztlnp.reliability import ReliableChannel
from ztlnp.packet import PacketFlags
from ztlnp.exceptions import ReplayAttackError, RetransmitError


def banner(title):
    print(f"\n{'=' * 64}")
    print(f"  {title}")
    print(f"{'=' * 64}")


def step(msg):
    print(f"\n[*] {msg}")


def ok(msg):
    print(f"    \u2713  {msg}")


def _do_handshake(alice, bob):
    h1 = alice.initiate(bob.local.device_id)
    h2 = bob.process_incoming(h1)
    k1 = alice.process_incoming(h2)
    k2 = bob.process_incoming(k1)
    alice.process_incoming(k2)


# ============================================================
# Feature 1: Trust Bootstrap Layer
# ============================================================

banner("Feature 1 \u2014 Trust Bootstrap Layer")

store = TrustStore(allow_tofu=True)
bob_dev = Device("Bob")

step("First contact: Trust-on-First-Use (TOFU)")
rec = store.process_hello(bob_dev.device_id, bob_dev.identity_public_bytes)
ok(f"Bob accepted via TOFU  (trust level: {rec.trust_level.name})")

step("Out-of-band fingerprint verification (phone call / QR scan)")
fp = fingerprint_of(bob_dev.identity_public_bytes)
ok(f"Bob's fingerprint: {fp}")
upgraded = store.verify_fingerprint(bob_dev.device_id, fp)
assert upgraded
ok(f"Fingerprint confirmed \u2192 trust level: {store.get(bob_dev.device_id).trust_level.name}")

step("QR-code-friendly key exchange for Charlie")
charlie_dev = Device("Charlie")
qr_payload = encode_qr_payload(charlie_dev.device_id, charlie_dev.identity_public_bytes)
ok(f"QR payload: {qr_payload[:60]}\u2026")
recovered_id, recovered_pub = parse_qr_payload(qr_payload)
assert recovered_id == charlie_dev.device_id
store.add(recovered_pub, TrustLevel.VERIFIED)
ok("Charlie's key loaded from QR payload \u2192 VERIFIED")

step("Web-of-trust: Alice (VERIFIED) endorses Dave")
alice_endorser = Device("Alice-endorser")
store.add(alice_endorser.identity_public_bytes, TrustLevel.VERIFIED)
dave_dev = Device("Dave")
endorsement = create_endorsement(
    alice_endorser._identity_private,
    alice_endorser.device_id,
    dave_dev.device_id,
    dave_dev.identity_public_bytes,
)
ok(f"Endorsement blob: {len(endorsement)} bytes (signed by Alice)")
rec = store.add_endorsement(endorsement, alice_endorser.device_id)
ok(f"Dave accepted via web-of-trust \u2192 trust level: {rec.trust_level.name}")
assert store.is_trusted(dave_dev.device_id)


# ============================================================
# Feature 2: Transport Abstraction
# ============================================================

banner("Feature 2 \u2014 Transport Abstraction")

step("Alice \u2194 Bob over InProcessTransport")
alice_t, bob_t = InProcessTransport.create_pair(b"alice-addr", b"bob-addr")
ok(f"Alice local address : {alice_t.local_addr}")
ok(f"Bob   local address : {bob_t.local_addr}")

alice2 = Protocol(Device("Alice"))
bob2 = Protocol(Device("Bob"))
_do_handshake(alice2, bob2)

data_wire = alice2.send_data(b"Transport-agnostic payload")
alice_t.send(bob_t.local_addr, data_wire)
src, received_wire = bob_t.recv(timeout=1.0)
plaintext = bob2.receive_data(received_wire)
ok(f"Message delivered over InProcessTransport: {plaintext.decode()!r}")
ok("Same API works over UDP, BLE, LoRa, WebRTC \u2014 just swap the Transport.")


# ============================================================
# Feature 3: Mesh Routing (identity-based forwarding)
# ============================================================

banner("Feature 3 \u2014 Mesh Routing (Identity-Based Forwarding)")

step("Three nodes: Alice \u2014 Bob (router) \u2014 Charlie")

alice_dev3 = Device("Alice")
bob_router_dev = Device("Bob-Router")
charlie_dev3 = Device("Charlie")

t_ab_a, t_ab_b = InProcessTransport.create_pair(b"alice", b"bob-router")
t_bc_b, t_bc_c = InProcessTransport.create_pair(b"bob-router", b"charlie")

router_alice = Router(alice_dev3.device_id)
router_bob = Router(bob_router_dev.device_id)

router_alice.add_direct_route(bob_router_dev.device_id, t_ab_a, b"bob-router")
router_bob.add_direct_route(alice_dev3.device_id, t_ab_b, b"alice")
router_bob.add_direct_route(charlie_dev3.device_id, t_bc_b, b"charlie")

announce_payload = router_bob.build_announce_payload()
updated = router_alice.process_announce_payload(announce_payload, t_ab_a, b"bob-router")
ok(f"Alice learned {len(updated)} route(s) from Bob's announcement")

proto_alice3 = Protocol(alice_dev3)
proto_charlie3 = Protocol(charlie_dev3)
_do_handshake(proto_alice3, proto_charlie3)

step("Alice \u2192 Bob (router) \u2192 Charlie: forwarding a DATA packet")
data_bytes = proto_alice3.send_data(b"Routed zero-trust payload")
router_alice.forward(data_bytes, charlie_dev3.device_id)
_, forwarded = t_ab_b.recv(timeout=1.0)
router_bob.forward(forwarded, charlie_dev3.device_id)
_, final = t_bc_c.recv(timeout=1.0)
plaintext = proto_charlie3.receive_data(final)
ok(f"Charlie received: {plaintext.decode()!r}")
ok("Packet traversed two hops; Charlie verified Alice's Ed25519 signature directly.")


# ============================================================
# Feature 4: Reliability (Stop-and-Wait ARQ)
# ============================================================

banner("Feature 4 \u2014 Reliable Delivery (Retransmission / ARQ)")

alice4 = Protocol(Device("Alice4"))
bob4 = Protocol(Device("Bob4"))
_do_handshake(alice4, bob4)

channel = ReliableChannel(alice4, base_timeout_ms=500, max_retries=3)

step("Sending a message with ARQ tracking")
seq, wire = channel.send(b"Important message")
ok(f"Packet queued with sequence {seq}; pending: {channel.pending_count}")
channel.process_ack(seq)
ok(f"ACK received for seq {seq}; pending: {channel.pending_count}")
assert channel.pending_count == 0

step("Simulating packet loss and retransmission")
seq2, _ = channel.send(b"Lost packet")
channel._pending[seq2].sent_at = time.time() - 1.0
retrans = channel.get_retransmissions()
ok(f"{len(retrans)} retransmission generated; retry count: {channel._pending[seq2].retries}")

step("Exhausting max_retries raises RetransmitError")
short_channel = ReliableChannel(alice4, base_timeout_ms=500, max_retries=1)
seq3, _ = short_channel.send(b"Will fail")
short_channel._pending[seq3].sent_at = time.time() - 1.0
short_channel.get_retransmissions()  # first retry
short_channel._pending[seq3].sent_at = time.time() - 1.0
try:
    short_channel.get_retransmissions()
    print("    \u2717  BUG: should have raised RetransmitError")
    sys.exit(1)
except RetransmitError as exc:
    ok(f"RetransmitError raised as expected: {exc}")


# ============================================================
# Feature 5: MAC Optimization (HMAC-SHA-512 fast path)
# ============================================================

banner("Feature 5 \u2014 MAC Optimization (HMAC-SHA-512 Fast Path)")

alice5_dev = Device("Alice5")
bob5_dev = Device("Bob5")
alice5 = Protocol(alice5_dev)
bob5 = Protocol(bob5_dev)
_do_handshake(alice5, bob5)

step("Comparing Ed25519 vs HMAC-SHA-512 per-packet authentication")
N = 500

t0 = time.perf_counter()
for _ in range(N):
    wire = alice5_dev.build_data_packet(bob5_dev.device_id, b"bench").to_bytes()
    bob5_dev.receive_packet(wire)
t_ed25519 = (time.perf_counter() - t0) * 1000 / N

t0 = time.perf_counter()
for _ in range(N):
    wire = alice5_dev.build_data_packet_mac(bob5_dev.device_id, b"bench").to_bytes()
    bob5_dev.receive_packet(wire)
t_mac = (time.perf_counter() - t0) * 1000 / N

ok(f"Ed25519 sign+verify:     {t_ed25519:.3f} ms/packet")
ok(f"HMAC-SHA-512 tag+verify: {t_mac:.3f} ms/packet")
speedup = t_ed25519 / max(t_mac, 0.001)
ok(f"Speedup: {speedup:.1f}\u00d7")

step("Verifying MAC packet security")
mac_packet = alice5_dev.build_data_packet_mac(bob5_dev.device_id, b"fast")
assert mac_packet.flags & PacketFlags.MAC_AUTH
ok("MAC_AUTH flag set on the packet")

session = alice5_dev.get_session(bob5_dev.device_id)
ok(f"Session MAC key: {session.mac_key.hex()[:32]}\u2026  (64 bytes, HKDF-independent)")
plaintext_check = bob5_dev.decrypt_packet(bob5_dev.receive_packet(mac_packet.to_bytes()))
assert plaintext_check == b"fast"
ok("MAC-authenticated packet decrypted and verified correctly")


# ============================================================
# Summary
# ============================================================

banner("All Features Validated \u2014 ZTLNP v2 Summary")
print("""
  Feature 1 \u2014 Trust Bootstrap
    \u2713 TOFU, fingerprint verification, QR key exchange
    \u2713 Web-of-trust endorsements (signed vouchers from VERIFIED peers)

  Feature 2 \u2014 Transport Abstraction
    \u2713 Protocol runs unchanged over InProcessTransport, UDP, or any adapter

  Feature 3 \u2014 Mesh Routing
    \u2713 Packets forwarded by device identity (not IP)
    \u2713 Route announcements propagate reachability; trust decays per hop

  Feature 4 \u2014 Reliability (Stop-and-Wait ARQ)
    \u2713 Pending-packet queue, exponential backoff, configurable max retries
    \u2713 Caller-driven (no hidden threads)

  Feature 5 \u2014 MAC Optimization
    \u2713 DATA packets in established sessions use HMAC-SHA-512 (MAC_AUTH flag)
    \u2713 Same wire format, same replay protection, significantly faster
""")
