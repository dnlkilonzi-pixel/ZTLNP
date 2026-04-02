"""
Tests for the ZTLNP reliability layer and MAC optimization.
"""

import struct
import time
import pytest

from ztlnp.device import Device
from ztlnp.protocol import Protocol, ProtocolState
from ztlnp.reliability import ReliableChannel, PendingPacket
from ztlnp.exceptions import RetransmitError
from ztlnp.crypto import CryptoEngine
from ztlnp.packet import PacketFlags


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def do_handshake(alice: Protocol, bob: Protocol) -> None:
    hello1 = alice.initiate(bob.local.device_id)
    hello2 = bob.process_incoming(hello1)
    ke1 = alice.process_incoming(hello2)
    ke2 = bob.process_incoming(ke1)
    alice.process_incoming(ke2)


# ---------------------------------------------------------------------------
# PendingPacket
# ---------------------------------------------------------------------------

class TestPendingPacket:
    def test_initially_not_due(self):
        p = PendingPacket(sequence=0, packet_bytes=b"x", next_timeout_ms=10_000)
        assert not p.is_due()

    def test_due_after_timeout(self):
        p = PendingPacket(
            sequence=0,
            packet_bytes=b"x",
            sent_at=time.time() - 2.0,
            next_timeout_ms=500,
        )
        assert p.is_due()

    def test_record_retransmit_increments_retries(self):
        p = PendingPacket(sequence=0, packet_bytes=b"x", next_timeout_ms=500)
        p.record_retransmit(base_timeout_ms=500, max_timeout_ms=16_000)
        assert p.retries == 1
        assert p.next_timeout_ms == 1000  # doubles

    def test_backoff_capped_at_max(self):
        p = PendingPacket(sequence=0, packet_bytes=b"x", next_timeout_ms=8_000)
        p.record_retransmit(base_timeout_ms=500, max_timeout_ms=10_000)
        assert p.next_timeout_ms == 10_000  # capped


# ---------------------------------------------------------------------------
# ReliableChannel – basic send / ACK
# ---------------------------------------------------------------------------

class TestReliableChannelBasic:
    def setup_method(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        self.alice = Protocol(alice_dev)
        self.bob = Protocol(bob_dev)
        do_handshake(self.alice, self.bob)
        self.alice_ch = ReliableChannel(self.alice)
        self.bob_ch = ReliableChannel(self.bob)

    def test_send_returns_sequence_and_wire(self):
        seq, wire = self.alice_ch.send(b"hello")
        assert isinstance(seq, int)
        assert len(wire) > 100

    def test_pending_count_after_send(self):
        self.alice_ch.send(b"msg1")
        self.alice_ch.send(b"msg2")
        assert self.alice_ch.pending_count == 2

    def test_ack_removes_from_pending(self):
        seq, _ = self.alice_ch.send(b"hello")
        assert self.alice_ch.pending_count == 1
        assert self.alice_ch.process_ack(seq)
        assert self.alice_ch.pending_count == 0

    def test_duplicate_ack_returns_false(self):
        seq, _ = self.alice_ch.send(b"hello")
        self.alice_ch.process_ack(seq)
        assert not self.alice_ch.process_ack(seq)

    def test_ack_unknown_sequence_returns_false(self):
        assert not self.alice_ch.process_ack(9999)

    def test_pending_sequences(self):
        s1, _ = self.alice_ch.send(b"a")
        s2, _ = self.alice_ch.send(b"b")
        assert sorted(self.alice_ch.pending_sequences) == sorted([s1, s2])

    def test_sent_packet_is_decryptable_by_receiver(self):
        _, wire = self.alice_ch.send(b"secret")
        plaintext = self.bob.receive_data(wire)
        assert plaintext == b"secret"


# ---------------------------------------------------------------------------
# ReliableChannel – retransmission
# ---------------------------------------------------------------------------

class TestReliableChannelRetransmit:
    def test_no_retransmissions_needed_when_not_due(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)
        ch = ReliableChannel(alice, base_timeout_ms=10_000)
        ch.send(b"data")
        assert ch.get_retransmissions() == []

    def test_retransmission_returned_when_overdue(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)
        ch = ReliableChannel(alice, base_timeout_ms=10_000)
        seq, _ = ch.send(b"data")
        # Force the packet to be overdue.
        ch._pending[seq].sent_at = time.time() - 20.0
        retrans = ch.get_retransmissions()
        assert len(retrans) == 1

    def test_retransmit_increments_retry_counter(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)
        ch = ReliableChannel(alice, base_timeout_ms=10_000)
        seq, _ = ch.send(b"data")
        ch._pending[seq].sent_at = time.time() - 20.0
        ch.get_retransmissions()
        assert ch._pending[seq].retries == 1

    def test_max_retries_raises(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        alice = Protocol(alice_dev)
        bob = Protocol(bob_dev)
        do_handshake(alice, bob)
        ch = ReliableChannel(alice, base_timeout_ms=10_000, max_retries=2)
        seq, _ = ch.send(b"data")

        # Exhaust retries.
        for _ in range(2):
            ch._pending[seq].sent_at = time.time() - 20.0
            ch.get_retransmissions()

        ch._pending[seq].sent_at = time.time() - 20.0
        with pytest.raises(RetransmitError):
            ch.get_retransmissions()

        # Packet should be removed after max retries.
        assert seq not in ch._pending


# ---------------------------------------------------------------------------
# MAC_AUTH optimization (Feature 5)
# ---------------------------------------------------------------------------

class TestMACAuth:
    def setup_method(self):
        self.alice_dev = Device("alice")
        self.bob_dev = Device("bob")
        alice = Protocol(self.alice_dev)
        bob = Protocol(self.bob_dev)
        do_handshake(alice, bob)

    def test_mac_data_packet_has_mac_auth_flag(self):
        packet = self.alice_dev.build_data_packet_mac(self.bob_dev.device_id, b"fast")
        assert packet.flags & PacketFlags.MAC_AUTH

    def test_mac_data_packet_is_decryptable(self):
        packet = self.alice_dev.build_data_packet_mac(self.bob_dev.device_id, b"fast path")
        wire = packet.to_bytes()
        received = self.bob_dev.receive_packet(wire)
        plaintext = self.bob_dev.decrypt_packet(received)
        assert plaintext == b"fast path"

    def test_regular_data_packet_has_no_mac_flag(self):
        packet = self.alice_dev.build_data_packet(self.bob_dev.device_id, b"slow path")
        assert not (packet.flags & PacketFlags.MAC_AUTH)

    def test_tampered_mac_packet_rejected(self):
        from ztlnp.exceptions import SignatureVerificationError
        packet = self.alice_dev.build_data_packet_mac(self.bob_dev.device_id, b"data")
        wire = bytearray(packet.to_bytes())
        wire[-1] ^= 0xFF  # corrupt HMAC tag
        with pytest.raises(SignatureVerificationError):
            self.bob_dev.receive_packet(bytes(wire))

    def test_mac_packet_replay_rejected(self):
        from ztlnp.exceptions import ReplayAttackError
        packet = self.alice_dev.build_data_packet_mac(self.bob_dev.device_id, b"once")
        wire = packet.to_bytes()
        self.bob_dev.receive_packet(wire)  # first delivery OK
        with pytest.raises(ReplayAttackError):
            self.bob_dev.receive_packet(wire)

    def test_both_sides_derive_same_mac_key(self):
        alice_session = self.alice_dev.get_session(self.bob_dev.device_id)
        bob_session = self.bob_dev.get_session(self.alice_dev.device_id)
        assert alice_session.mac_key == bob_session.mac_key
        assert len(alice_session.mac_key) == 64

    def test_session_key_and_mac_key_are_different(self):
        session = self.alice_dev.get_session(self.bob_dev.device_id)
        # session_key is 32 bytes, mac_key is 64 bytes — they're different lengths.
        # Even if we compare first 32 bytes, they should differ.
        assert session.session_key != session.mac_key[:32]

    def test_reliable_channel_mac_mode(self):
        alice = Protocol(self.alice_dev)
        bob = Protocol(self.bob_dev)
        # Re-establish because handshake already consumed keys for a second pair.
        alice2_dev = Device("alice2")
        bob2_dev = Device("bob2")
        alice2 = Protocol(alice2_dev)
        bob2 = Protocol(bob2_dev)
        do_handshake(alice2, bob2)

        ch = ReliableChannel(alice2, use_mac=True)
        seq, wire = ch.send(b"mac-fast-message")
        # Check the MAC_AUTH flag is set on the wire.
        flags = struct.unpack_from("!H", wire, 6)[0]
        assert flags & PacketFlags.MAC_AUTH
        # Bob can still decrypt it.
        plaintext = bob2.receive_data(wire)
        assert plaintext == b"mac-fast-message"


# ---------------------------------------------------------------------------
# MAC cryptographic primitives (unit tests)
# ---------------------------------------------------------------------------

class TestMACPrimitives:
    def test_compute_mac_length(self):
        key = b"\xAA" * 64
        tag = CryptoEngine.compute_mac(key, b"data")
        assert len(tag) == 64

    def test_verify_mac_correct(self):
        key = b"\xAA" * 64
        data = b"authenticated data"
        tag = CryptoEngine.compute_mac(key, data)
        assert CryptoEngine.verify_mac(key, data, tag)

    def test_verify_mac_wrong_key(self):
        key1 = b"\xAA" * 64
        key2 = b"\xBB" * 64
        tag = CryptoEngine.compute_mac(key1, b"data")
        assert not CryptoEngine.verify_mac(key2, b"data", tag)

    def test_verify_mac_tampered_data(self):
        key = b"\xAA" * 64
        tag = CryptoEngine.compute_mac(key, b"original")
        assert not CryptoEngine.verify_mac(key, b"tampered", tag)

    def test_derive_mac_key_length(self):
        shared = b"\x00" * 32
        key = CryptoEngine.derive_mac_key(shared, b"\x01" * 32, b"\x02" * 32)
        assert len(key) == 64

    def test_derive_mac_key_differs_from_session_key(self):
        shared = b"\xAB" * 32
        init_id = b"\x01" * 32
        resp_id = b"\x02" * 32
        sk = CryptoEngine.derive_session_key(shared, init_id, resp_id)
        mk = CryptoEngine.derive_mac_key(shared, init_id, resp_id)
        assert sk != mk[:32]
