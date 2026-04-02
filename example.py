#!/usr/bin/env python3
"""
ZTLNP Demo — Zero Trust Local Network Protocol
================================================

This script demonstrates a complete ZTLNP session between two in-process
"devices".  Every packet is signed with the sender's Ed25519 identity key and
every payload is encrypted with AES-256-GCM — even though Alice and Bob are on
the same machine.

Concepts shown
--------------
1. Device identity key generation
2. Full HELLO → KEY_EXCHANGE handshake
3. Authenticated, encrypted DATA exchange
4. Replay-attack rejection
5. Graceful session teardown (BYE)
"""

from __future__ import annotations

import sys
import time

from ztlnp.device import Device
from ztlnp.protocol import Protocol, ProtocolState
from ztlnp.exceptions import ReplayAttackError, SignatureVerificationError


def banner(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def step(msg: str) -> None:
    print(f"\n[*] {msg}")


def ok(msg: str) -> None:
    print(f"    ✓  {msg}")


def warn(msg: str) -> None:
    print(f"    ⚠  {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# 1. Create two devices
# ---------------------------------------------------------------------------

banner("ZTLNP Demo")

step("Creating Alice and Bob…")
alice_dev = Device("Alice")
bob_dev = Device("Bob")
ok(f"Alice device ID: {alice_dev.device_id.hex()[:32]}…")
ok(f"Bob   device ID: {bob_dev.device_id.hex()[:32]}…")
ok("Both devices generated Ed25519 identity key pairs.")

# ---------------------------------------------------------------------------
# 2. Handshake
# ---------------------------------------------------------------------------

step("Starting HELLO → KEY_EXCHANGE handshake (zero implicit trust)…")

alice = Protocol(alice_dev)
bob = Protocol(bob_dev)

# Alice initiates.
hello_from_alice = alice.initiate(bob_dev.device_id)
ok(f"Alice → Bob  HELLO  ({len(hello_from_alice)} bytes)")

# Bob receives Alice's HELLO and sends its own.
hello_from_bob = bob.process_incoming(hello_from_alice)
ok(f"Bob   → Alice HELLO ({len(hello_from_bob)} bytes)")

# Alice receives Bob's HELLO, completes key exchange, sends KEY_EXCHANGE.
ke_from_alice = alice.process_incoming(hello_from_bob)
ok(f"Alice → Bob  KEY_EXCHANGE ({len(ke_from_alice)} bytes)")

# Bob verifies KEY_EXCHANGE, completes its side, sends confirmation.
ke_from_bob = bob.process_incoming(ke_from_alice)
ok(f"Bob   → Alice KEY_EXCHANGE ({len(ke_from_bob)} bytes)")

# Alice receives confirmation.
alice.process_incoming(ke_from_bob)

assert alice.state == ProtocolState.ESTABLISHED
assert bob.state == ProtocolState.ESTABLISHED
ok("Handshake complete — both sides are in ESTABLISHED state.")

alice_session = alice_dev.get_session(bob_dev.device_id)
bob_session = bob_dev.get_session(alice_dev.device_id)
assert alice_session.session_key == bob_session.session_key
ok(f"Shared session key: {alice_session.session_key.hex()[:32]}…")
ok("Both sides derived the same AES-256-GCM session key via X25519 + HKDF.")

# ---------------------------------------------------------------------------
# 3. Authenticated, encrypted data exchange
# ---------------------------------------------------------------------------

banner("Authenticated & Encrypted Data Exchange")

messages = [
    b"Hello Bob, this message is signed and encrypted!",
    b"Even on the same LAN, I trust nobody implicitly.",
    b"Zero Trust means verify every single packet.",
]

for i, plaintext in enumerate(messages, 1):
    wire = alice.send_data(plaintext)
    recovered = bob.receive_data(wire)
    assert recovered == plaintext
    step(f"Message {i}: Alice → Bob")
    ok(f"Plaintext  : {plaintext.decode()}")
    ok(f"Wire bytes : {wire.hex()[:64]}… ({len(wire)} bytes total)")
    ok("Verified  : Ed25519 signature ✓  AES-256-GCM auth ✓  Replay check ✓")

# ---------------------------------------------------------------------------
# 4. Replay-attack rejection
# ---------------------------------------------------------------------------

banner("Replay-Attack Prevention")

step("Alice sends a DATA packet, Bob receives it normally…")
wire = alice.send_data(b"legitimate packet")
bob.receive_data(wire)
ok("First delivery accepted.")

step("Attacker replays the same packet bytes to Bob…")
try:
    bob_dev.receive_packet(wire)
    warn("BUG: replay was accepted!")
    sys.exit(1)
except ReplayAttackError as exc:
    ok(f"Replay correctly rejected: {exc}")

# ---------------------------------------------------------------------------
# 5. Tamper detection
# ---------------------------------------------------------------------------

banner("Tamper Detection")

step("Alice sends a DATA packet; attacker flips a bit in the payload…")
wire = bytearray(alice.send_data(b"tamper me"))
wire[105] ^= 0xFF  # flip a bit somewhere in the payload
try:
    bob_dev.receive_packet(bytes(wire))
    warn("BUG: tampered packet was accepted!")
    sys.exit(1)
except (SignatureVerificationError, Exception) as exc:
    ok(f"Tampered packet rejected: {type(exc).__name__}")

# ---------------------------------------------------------------------------
# 6. Session teardown
# ---------------------------------------------------------------------------

banner("Graceful Session Teardown (BYE)")

step("Alice sends a BYE packet to Bob…")
bye_wire = alice_dev.build_bye_packet(bob_dev.device_id).to_bytes()
bob.process_incoming(bye_wire)
assert bob.state == ProtocolState.CLOSED
ok("Bob closed the session after receiving BYE.")
ok(f"Bob state: {bob.state.name}")

print()
banner("Demo Complete — ZTLNP properties validated")
print("""
  Every packet is authenticated with Ed25519 (per-packet verification).
  Every payload is encrypted with AES-256-GCM.
  Replay attacks are blocked by timestamp bounds + sequence-number windows.
  Device identity is cryptographic (not IP/MAC-based) — zero implicit trust.
""")
