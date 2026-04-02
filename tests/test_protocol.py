"""
Tests for the ZTLNP protocol state machine and full handshake lifecycle.

These tests simulate two in-process ``Protocol`` instances that exchange
serialised packet bytes directly (no network I/O needed).
"""

import time
import struct
import pytest

from ztlnp.device import Device
from ztlnp.protocol import Protocol, ProtocolState
from ztlnp.session import Session, MAX_CLOCK_SKEW_MS
from ztlnp.exceptions import (
    HandshakeError,
    SignatureVerificationError,
    ReplayAttackError,
    SessionNotFoundError,
)
from ztlnp.packet import Packet, PacketType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def do_handshake(initiator: Protocol, responder: Protocol) -> None:
    """Drive a complete ZTLNP handshake between two Protocol instances."""
    # Step 1: initiator sends HELLO
    hello1 = initiator.initiate(responder.local.device_id)

    # Step 2: responder receives HELLO, sends back its HELLO
    hello2 = responder.process_incoming(hello1)
    assert hello2 is not None

    # Step 3: initiator receives responder's HELLO, sends KEY_EXCHANGE
    ke1 = initiator.process_incoming(hello2)
    assert ke1 is not None

    # Step 4: responder receives KEY_EXCHANGE, sends its KEY_EXCHANGE back
    ke2 = responder.process_incoming(ke1)
    assert ke2 is not None

    # Step 5: initiator receives KEY_EXCHANGE confirmation
    result = initiator.process_incoming(ke2)
    assert result is None


# ---------------------------------------------------------------------------
# Device tests
# ---------------------------------------------------------------------------

class TestDevice:
    def test_device_id_is_32_bytes(self):
        d = Device("alpha")
        assert len(d.device_id) == 32

    def test_different_devices_have_different_ids(self):
        d1, d2 = Device(), Device()
        assert d1.device_id != d2.device_id

    def test_identity_public_bytes_is_32_bytes(self):
        d = Device()
        assert len(d.identity_public_bytes) == 32

    def test_get_session_raises_when_none(self):
        d = Device()
        with pytest.raises(SessionNotFoundError):
            d.get_session(b"\x00" * 32)

    def test_has_session_returns_false_initially(self):
        d = Device()
        assert not d.has_session(b"\x00" * 32)

    def test_remove_session_noop_when_missing(self):
        d = Device()
        d.remove_session(b"\x00" * 32)  # Should not raise.

    def test_build_hello_contains_both_public_keys(self):
        d = Device()
        hello = d.build_hello_packet()
        assert len(hello.payload) == 64
        assert hello.payload[:32] == d.identity_public_bytes


# ---------------------------------------------------------------------------
# Protocol handshake
# ---------------------------------------------------------------------------

class TestHandshake:
    def test_full_handshake_reaches_established(self):
        alice = Protocol(Device("alice"))
        bob = Protocol(Device("bob"))
        do_handshake(alice, bob)
        assert alice.state == ProtocolState.ESTABLISHED
        assert bob.state == ProtocolState.ESTABLISHED

    def test_both_sessions_derive_same_key(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)

        alice_session = alice_dev.get_session(bob_dev.device_id)
        bob_session = bob_dev.get_session(alice_dev.device_id)
        assert alice_session.session_key == bob_session.session_key

    def test_cannot_initiate_twice(self):
        proto = Protocol(Device())
        proto.initiate(b"\x01" * 32)
        with pytest.raises(HandshakeError):
            proto.initiate(b"\x01" * 32)

    def test_closed_protocol_rejects_packets(self):
        alice = Protocol(Device("alice"))
        bob = Protocol(Device("bob"))
        do_handshake(alice, bob)

        bye = alice.local.build_bye_packet(bob.local.device_id).to_bytes()
        bob.process_incoming(bye)
        assert bob.state == ProtocolState.CLOSED
        with pytest.raises(HandshakeError):
            bob.process_incoming(alice.local.build_hello_packet().to_bytes())


# ---------------------------------------------------------------------------
# Data exchange
# ---------------------------------------------------------------------------

class TestDataExchange:
    def test_send_receive_roundtrip(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)

        plaintext = b"hello from alice"
        data_pkt = alice.send_data(plaintext)
        recovered = bob.receive_data(data_pkt)
        assert recovered == plaintext

    def test_multiple_messages_roundtrip(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)

        messages = [b"msg1", b"msg2", b"msg3"]
        for msg in messages:
            wire = alice.send_data(msg)
            assert bob.receive_data(wire) == msg

    def test_bidirectional_exchange(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)

        a_to_b = alice.send_data(b"alice->bob")
        b_to_a = bob.send_data(b"bob->alice")
        assert bob.receive_data(a_to_b) == b"alice->bob"
        assert alice.receive_data(b_to_a) == b"bob->alice"

    def test_data_requires_established_session(self):
        proto = Protocol(Device())
        with pytest.raises(HandshakeError):
            proto.send_data(b"premature")

    def test_large_payload(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)

        payload = b"X" * 65536
        wire = alice.send_data(payload)
        assert bob.receive_data(wire) == payload


# ---------------------------------------------------------------------------
# Security: signature verification
# ---------------------------------------------------------------------------

class TestSignatureVerification:
    def test_tampered_payload_rejected(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)

        wire = bytearray(alice.send_data(b"legit"))
        # Flip a bit in the payload area (after the fixed header).
        from ztlnp.packet import _HEADER_SIZE
        wire[_HEADER_SIZE] ^= 0xFF
        with pytest.raises((SignatureVerificationError, Exception)):
            bob_dev.receive_packet(bytes(wire))

    def test_tampered_signature_rejected(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)

        wire = bytearray(alice.send_data(b"legit"))
        # Corrupt last byte of signature.
        wire[-1] ^= 0xFF
        with pytest.raises(SignatureVerificationError):
            bob_dev.receive_packet(bytes(wire))

    def test_hello_with_wrong_signature_rejected(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        # Build a HELLO from alice but tamper with the signature.
        hello = alice_dev.build_hello_packet(bob_dev.device_id)
        hello.signature = b"\x00" * 64
        with pytest.raises(SignatureVerificationError):
            bob_dev.receive_packet(hello.to_bytes())


# ---------------------------------------------------------------------------
# Security: replay attack prevention
# ---------------------------------------------------------------------------

class TestReplayPrevention:
    def test_duplicate_sequence_rejected(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)

        wire = alice.send_data(b"first")
        bob.receive_data(wire)  # First delivery: OK.
        with pytest.raises(ReplayAttackError):
            bob_dev.receive_packet(wire)  # Replay: must be rejected.

    def test_stale_timestamp_rejected(self):
        session = Session(
            peer_id=b"\x01" * 32,
            peer_ed25519_public=b"\x02" * 32,
            session_key=b"\x03" * 32,
            mac_key=b"\x04" * 64,
        )
        stale_ts = int(time.time() * 1000) - (MAX_CLOCK_SKEW_MS + 1_000)
        with pytest.raises(ReplayAttackError, match="timestamp"):
            session.check_replay(sequence=1, timestamp_ms=stale_ts)

    def test_future_timestamp_rejected(self):
        session = Session(
            peer_id=b"\x01" * 32,
            peer_ed25519_public=b"\x02" * 32,
            session_key=b"\x03" * 32,
            mac_key=b"\x04" * 64,
        )
        future_ts = int(time.time() * 1000) + (MAX_CLOCK_SKEW_MS + 1_000)
        with pytest.raises(ReplayAttackError, match="timestamp"):
            session.check_replay(sequence=1, timestamp_ms=future_ts)

    def test_very_old_sequence_in_window_rejected(self):
        session = Session(
            peer_id=b"\x01" * 32,
            peer_ed25519_public=b"\x02" * 32,
            session_key=b"\x03" * 32,
            mac_key=b"\x04" * 64,
        )
        now_ms = int(time.time() * 1000)
        # Advance the window to sequence 100.
        for seq in range(1, 101):
            session.check_replay(seq, now_ms)
        # Sequence 0 is now outside the replay window.
        with pytest.raises(ReplayAttackError, match="Sequence number"):
            session.check_replay(0, now_ms)


# ---------------------------------------------------------------------------
# Session teardown (BYE)
# ---------------------------------------------------------------------------

class TestSessionTeardown:
    def test_bye_closes_session_on_receiver(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)

        bye = alice_dev.build_bye_packet(bob_dev.device_id).to_bytes()
        bob.process_incoming(bye)
        assert bob.state == ProtocolState.CLOSED
        assert not bob_dev.has_session(alice_dev.device_id)

    def test_after_bye_send_data_raises(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)

        bye = alice_dev.build_bye_packet(bob_dev.device_id).to_bytes()
        bob.process_incoming(bye)
        with pytest.raises(HandshakeError):
            bob.send_data(b"too late")
