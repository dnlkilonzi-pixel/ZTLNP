"""
Tests for the ZTLNP sliding-window ARQ channel.
"""

import pytest

from ztlnp.sliding_window import (
    SlidingWindowChannel,
    SackFrame,
    WindowedPacket,
)
from ztlnp.device import Device
from ztlnp.protocol import Protocol, ProtocolState
from ztlnp.exceptions import RetransmitError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def do_handshake(alice: Protocol, bob: Protocol) -> None:
    h1 = alice.initiate(bob.local.device_id)
    h2 = bob.process_incoming(h1)
    k1 = alice.process_incoming(h2)
    k2 = bob.process_incoming(k1)
    alice.process_incoming(k2)


def make_pair() -> tuple:
    alice = Protocol(Device("alice"))
    bob = Protocol(Device("bob"))
    do_handshake(alice, bob)
    return alice, bob


# ---------------------------------------------------------------------------
# SackFrame serialisation
# ---------------------------------------------------------------------------

class TestSackFrame:
    def test_cumulative_roundtrip(self):
        sack = SackFrame(cum_ack=42)
        data = sack.encode()
        sack2 = SackFrame.decode(data)
        assert sack2.cum_ack == 42
        assert sack2.blocks == []

    def test_selective_roundtrip(self):
        sack = SackFrame(cum_ack=10, blocks=[(15, 17), (20, 22)])
        data = sack.encode()
        sack2 = SackFrame.decode(data)
        assert sack2.cum_ack == 10
        assert sack2.blocks == [(15, 17), (20, 22)]

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            SackFrame.decode(b"\x01\x00")

    def test_truncated_blocks_raises(self):
        sack = SackFrame(cum_ack=5, blocks=[(8, 10)])
        data = sack.encode()[:-4]  # truncate last block
        with pytest.raises(ValueError, match="truncated"):
            SackFrame.decode(data)

    def test_all_acked_cumulative(self):
        sack = SackFrame(cum_ack=4)
        acked = sack.all_acked()
        assert acked == {0, 1, 2, 3, 4}

    def test_all_acked_with_blocks(self):
        sack = SackFrame(cum_ack=3, blocks=[(6, 8)])
        acked = sack.all_acked()
        assert acked >= {0, 1, 2, 3, 6, 7, 8}


# ---------------------------------------------------------------------------
# WindowedPacket
# ---------------------------------------------------------------------------

class TestWindowedPacket:
    def test_not_due_immediately(self):
        wp = WindowedPacket(sequence=1, packet_bytes=b"x", next_timeout_ms=1_000)
        assert not wp.is_due()

    def test_backoff_doubles(self):
        wp = WindowedPacket(sequence=1, packet_bytes=b"x", next_timeout_ms=100.0)
        wp.record_retransmit(base_ms=100.0, max_ms=1_600.0)
        assert wp.next_timeout_ms == 200.0
        wp.record_retransmit(base_ms=100.0, max_ms=1_600.0)
        assert wp.next_timeout_ms == 400.0

    def test_backoff_caps_at_max(self):
        wp = WindowedPacket(sequence=1, packet_bytes=b"x", next_timeout_ms=1_000.0)
        for _ in range(10):
            wp.record_retransmit(base_ms=100.0, max_ms=1_600.0)
        assert wp.next_timeout_ms == 1_600.0


# ---------------------------------------------------------------------------
# SlidingWindowChannel — send path
# ---------------------------------------------------------------------------

class TestSlidingWindowSend:
    def setup_method(self):
        self.alice, self.bob = make_pair()

    def test_send_returns_seq_and_wire(self):
        channel = SlidingWindowChannel(self.alice, window_size=4)
        seq, wire = channel.send(b"hello")
        assert seq is not None
        assert wire is not None
        assert len(wire) > 100

    def test_send_fills_window(self):
        channel = SlidingWindowChannel(self.alice, window_size=4)
        for _ in range(4):
            seq, wire = channel.send(b"data")
            assert seq is not None
        assert channel.in_flight == 4

    def test_send_returns_none_when_window_full(self):
        channel = SlidingWindowChannel(self.alice, window_size=2)
        channel.send(b"one")
        channel.send(b"two")
        seq, wire = channel.send(b"three")
        assert seq is None
        assert wire is None

    def test_can_send_returns_false_when_full(self):
        channel = SlidingWindowChannel(self.alice, window_size=1)
        channel.send(b"one")
        assert not channel.can_send()

    def test_can_send_returns_true_when_empty(self):
        channel = SlidingWindowChannel(self.alice, window_size=8)
        assert channel.can_send()

    def test_in_flight_count(self):
        channel = SlidingWindowChannel(self.alice, window_size=8)
        assert channel.in_flight == 0
        channel.send(b"a")
        assert channel.in_flight == 1
        channel.send(b"b")
        assert channel.in_flight == 2


# ---------------------------------------------------------------------------
# SlidingWindowChannel — SACK processing (ACK path)
# ---------------------------------------------------------------------------

class TestSlidingWindowSack:
    def setup_method(self):
        self.alice, self.bob = make_pair()

    def test_process_sack_removes_acked(self):
        channel = SlidingWindowChannel(self.alice, window_size=4)
        seq1, wire1 = channel.send(b"one")
        seq2, wire2 = channel.send(b"two")
        seq3, wire3 = channel.send(b"three")

        # ACK seq1 and seq2 via cumulative ACK.
        sack = SackFrame(cum_ack=seq2, blocks=[])
        removed = channel.process_sack(sack)
        assert removed >= 1  # at least seq1 is removed
        assert seq1 not in channel._send_window
        assert seq2 not in channel._send_window
        assert seq3 in channel._send_window

    def test_process_sack_with_selective_blocks(self):
        channel = SlidingWindowChannel(self.alice, window_size=8)
        seqs = []
        for i in range(4):
            seq, _ = channel.send(f"pkt{i}".encode())
            seqs.append(seq)

        # Selective-ACK: skip seq[1], ack seq[0], seq[2], seq[3]
        sack = SackFrame(cum_ack=seqs[0], blocks=[(seqs[2], seqs[3])])
        channel.process_sack(sack)

        assert seqs[0] not in channel._send_window
        assert seqs[1] in channel._send_window  # still pending
        assert seqs[2] not in channel._send_window
        assert seqs[3] not in channel._send_window


# ---------------------------------------------------------------------------
# SlidingWindowChannel — retransmission
# ---------------------------------------------------------------------------

class TestSlidingWindowRetransmit:
    def setup_method(self):
        self.alice, self.bob = make_pair()

    def test_no_retransmissions_immediately_after_send(self):
        channel = SlidingWindowChannel(
            self.alice, window_size=4, base_timeout_ms=10_000
        )
        channel.send(b"data")
        retrans = channel.get_retransmissions()
        assert retrans == []

    def test_retransmit_error_after_max_retries(self):
        channel = SlidingWindowChannel(
            self.alice, window_size=4, base_timeout_ms=0, max_retries=2
        )
        channel.send(b"unacked")

        # With max_retries=2 and base_timeout_ms=0, the packet becomes due
        # immediately.  First two calls retransmit (retries 0→1, 1→2);
        # the third call sees retries >= max_retries and raises.
        channel.get_retransmissions()  # retries: 0 → 1
        channel.get_retransmissions()  # retries: 1 → 2
        with pytest.raises(RetransmitError):
            channel.get_retransmissions()  # retries: 2 >= max_retries → fail

    def test_retransmit_returns_wire_bytes_when_due(self):
        channel = SlidingWindowChannel(
            self.alice, window_size=4, base_timeout_ms=0, max_retries=5
        )
        _, wire = channel.send(b"retransmit me")
        # Force all packets to be due by zeroing sent_at.
        for wp in channel._send_window.values():
            wp.sent_at = 0.0

        retrans = channel.get_retransmissions()
        assert len(retrans) == 1


# ---------------------------------------------------------------------------
# SlidingWindowChannel — window properties
# ---------------------------------------------------------------------------

class TestSlidingWindowProperties:
    def setup_method(self):
        self.alice, self.bob = make_pair()

    def test_window_size_property(self):
        channel = SlidingWindowChannel(self.alice, window_size=32)
        assert channel.window_size == 32

    def test_recv_next_starts_at_minus_1(self):
        channel = SlidingWindowChannel(self.alice)
        assert channel.recv_next == -1

    def test_send_base_starts_at_zero(self):
        channel = SlidingWindowChannel(self.alice)
        assert channel.send_base == 0


# ---------------------------------------------------------------------------
# SlidingWindowChannel — receive path
# ---------------------------------------------------------------------------

class TestSlidingWindowReceive:
    def setup_method(self):
        self.alice, self.bob = make_pair()

    def test_in_order_delivery(self):
        sender = SlidingWindowChannel(self.alice, window_size=8)
        receiver = SlidingWindowChannel(self.bob, window_size=8)

        seq, wire = sender.send(b"hello world")
        plaintext, sack = receiver.receive(wire)
        assert plaintext == b"hello world"
        assert sack is not None
        assert sack.cum_ack == seq

    def test_multiple_in_order_packets(self):
        sender = SlidingWindowChannel(self.alice, window_size=8)
        receiver = SlidingWindowChannel(self.bob, window_size=8)

        payloads = [f"packet{i}".encode() for i in range(4)]
        for msg in payloads:
            seq, wire = sender.send(msg)
            plaintext, sack = receiver.receive(wire)
            assert plaintext == msg

    def test_sack_frame_reflects_received_state(self):
        sender = SlidingWindowChannel(self.alice, window_size=8)
        receiver = SlidingWindowChannel(self.bob, window_size=8)

        seq0, wire0 = sender.send(b"first")
        _, sack = receiver.receive(wire0)
        assert sack.cum_ack == seq0

    def test_build_sack_ack_returns_bytes(self):
        sender = SlidingWindowChannel(self.alice, window_size=4)
        receiver = SlidingWindowChannel(self.bob, window_size=4)

        _, wire = sender.send(b"ack me")
        plaintext, sack = receiver.receive(wire)
        ack_bytes = receiver.build_sack_ack(sack)
        assert isinstance(ack_bytes, bytes)
        assert len(ack_bytes) > 100


# ---------------------------------------------------------------------------
# MAC path in sliding window
# ---------------------------------------------------------------------------

class TestSlidingWindowMac:
    def test_send_with_mac(self):
        alice, bob = make_pair()
        channel = SlidingWindowChannel(alice, window_size=4, use_mac=True)
        seq, wire = channel.send(b"mac data")
        assert seq is not None
        # MAC_AUTH flag should be set
        from ztlnp.packet import PacketFlags
        flags = int.from_bytes(wire[6:8], "big")
        assert flags & PacketFlags.MAC_AUTH

    def test_receive_mac_packet(self):
        alice, bob = make_pair()
        sender = SlidingWindowChannel(alice, window_size=4, use_mac=True)
        receiver = SlidingWindowChannel(bob, window_size=4)

        _, wire = sender.send(b"mac hello")
        plaintext, sack = receiver.receive(wire)
        assert plaintext == b"mac hello"
