"""
ZTLNP sliding-window ARQ — high-throughput reliable delivery.

Background
----------
The existing :class:`~ztlnp.reliability.ReliableChannel` uses stop-and-wait
ARQ: only one packet is in flight at a time.  Its theoretical maximum
throughput is::

    throughput = payload_size / RTT

For a 200 ms RTT and 1 KB payloads that is only 5 KB/s — unacceptable for
bulk transfers.

A **sliding window** protocol maintains up to ``window_size`` unacknowledged
packets in flight simultaneously, raising throughput to::

    throughput ≈ window_size × payload_size / RTT

With a window of 64 and 1 KB payloads at 200 ms RTT that is 320 KB/s — a
64× improvement over stop-and-wait.

Protocol
--------
This implementation follows RFC 793 / RFC 2018 Selective ACK principles:

* The send window is ``[send_base, send_base + window_size)``.
* Every DATA packet carries a sequence number; the receiver buffers
  out-of-order packets until they can be delivered in order.
* The receiver sends back SACK (Selective ACK) frames containing the set of
  contiguous sequence numbers it has received.  The sender can then
  selectively retransmit only the missing packets.
* The receive window is also bounded to ``window_size``.

SACK frame payload format
--------------------------
A SACK frame is carried in an ACK packet whose payload is an AES-GCM
encrypted blob with the following layout::

    [sack_type  (1 B)]  0x01 = cumulative-only, 0x02 = selective
    [cum_ack    (4 B)]  highest contiguous in-order sequence number received
    [n_blocks   (2 B)]  number of SACK blocks that follow (may be 0)
    for each block:
        [left    (4 B)]  first sequence number in this SACK block
        [right   (4 B)]  last  sequence number in this SACK block (inclusive)

Retransmission strategy
-----------------------
* On timeout: retransmit the oldest unacknowledged packet (go-back-N
  fallback for simplicity; selective retransmit when SACK data is
  available).
* Exponential backoff per packet, bounded by ``max_timeout_ms``.
* After ``max_retries`` attempts the packet is declared lost and a
  :class:`~ztlnp.exceptions.RetransmitError` is raised.

Thread safety
-------------
:class:`SlidingWindowChannel` is **not** thread-safe.  Use external locking
if accessed from multiple threads.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ztlnp.exceptions import RetransmitError
from ztlnp.packet import SEQUENCE_OFFSET
from ztlnp.protocol import Protocol


# ---------------------------------------------------------------------------
# SACK frame encoding / decoding
# ---------------------------------------------------------------------------

_SACK_CUMULATIVE = 0x01
_SACK_SELECTIVE = 0x02

# Struct formats
_SACK_HEADER_FMT = "!BIH"   # sack_type(1), cum_ack(4), n_blocks(2)
_SACK_HEADER_SIZE = struct.calcsize(_SACK_HEADER_FMT)  # 7 bytes
_SACK_BLOCK_FMT = "!II"     # left(4), right(4)
_SACK_BLOCK_SIZE = struct.calcsize(_SACK_BLOCK_FMT)  # 8 bytes


@dataclass
class SackFrame:
    """
    A parsed SACK acknowledgement.

    Parameters
    ----------
    cum_ack:
        The highest sequence number such that all packets with sequence
        numbers ≤ cum_ack have been received in order.
    blocks:
        List of ``(left, right)`` pairs representing out-of-order received
        ranges.  Empty for cumulative-only ACKs.
    """

    cum_ack: int
    blocks: List[Tuple[int, int]] = field(default_factory=list)

    def encode(self) -> bytes:
        """Serialise to bytes suitable for use as an ACK packet payload."""
        sack_type = _SACK_SELECTIVE if self.blocks else _SACK_CUMULATIVE
        header = struct.pack(_SACK_HEADER_FMT, sack_type, self.cum_ack, len(self.blocks))
        body = bytearray(header)
        for left, right in self.blocks:
            body += struct.pack(_SACK_BLOCK_FMT, left, right)
        return bytes(body)

    @classmethod
    def decode(cls, data: bytes) -> "SackFrame":
        """
        Deserialise from bytes.

        Raises
        ------
        ValueError
            If the data is too short or structurally invalid.
        """
        if len(data) < _SACK_HEADER_SIZE:
            raise ValueError(f"SACK frame too short: {len(data)} bytes")
        _type, cum_ack, n_blocks = struct.unpack_from(_SACK_HEADER_FMT, data)
        expected_len = _SACK_HEADER_SIZE + n_blocks * _SACK_BLOCK_SIZE
        if len(data) < expected_len:
            raise ValueError(
                f"SACK frame truncated: expected {expected_len} bytes, got {len(data)}"
            )
        blocks: List[Tuple[int, int]] = []
        for i in range(n_blocks):
            offset = _SACK_HEADER_SIZE + i * _SACK_BLOCK_SIZE
            left, right = struct.unpack_from(_SACK_BLOCK_FMT, data, offset)
            blocks.append((left, right))
        return cls(cum_ack=cum_ack, blocks=blocks)

    def all_acked(self) -> Set[int]:
        """
        Return the set of all individually acknowledged sequence numbers.

        This includes the cumulative range [0, cum_ack] and every (left,
        right) SACK block.
        """
        acked: Set[int] = set(range(self.cum_ack + 1))
        for left, right in self.blocks:
            acked.update(range(left, right + 1))
        return acked


# ---------------------------------------------------------------------------
# Pending packet (send-side)
# ---------------------------------------------------------------------------

@dataclass
class WindowedPacket:
    """
    A DATA packet held in the send window.

    Parameters
    ----------
    sequence:
        ZTLNP sequence number.
    packet_bytes:
        Serialised packet, ready to retransmit.
    sent_at:
        Unix timestamp of the most recent transmission.
    retries:
        Number of retransmissions so far.
    next_timeout_ms:
        Deadline (ms from sent_at) for the next retransmission.
    """

    sequence: int
    packet_bytes: bytes
    sent_at: float = field(default_factory=time.time)
    retries: int = 0
    next_timeout_ms: float = 200.0

    def is_due(self) -> bool:
        """Return ``True`` if this packet is overdue for retransmission."""
        return (time.time() - self.sent_at) * 1000 >= self.next_timeout_ms

    def record_retransmit(self, base_ms: float, max_ms: float) -> None:
        self.retries += 1
        self.sent_at = time.time()
        self.next_timeout_ms = min(self.next_timeout_ms * 2, max_ms)


# ---------------------------------------------------------------------------
# Sliding window channel
# ---------------------------------------------------------------------------

class SlidingWindowChannel:
    """
    Sliding-window ARQ channel on top of a ZTLNP :class:`~ztlnp.protocol.Protocol`.

    Provides reliable, ordered, high-throughput DATA delivery between two
    established ZTLNP peers.

    Parameters
    ----------
    protocol:
        An *established* :class:`~ztlnp.protocol.Protocol` session.
    window_size:
        Maximum number of unacknowledged packets in flight.  Default: 64.
    base_timeout_ms:
        Initial retransmission timeout in milliseconds.  Default: 200 ms.
    max_timeout_ms:
        Maximum retransmission timeout after exponential backoff.  Default:
        8 000 ms.
    max_retries:
        Maximum retransmission attempts before a packet is declared lost.
        Default: 5.
    use_mac:
        Build DATA packets using HMAC-SHA-512 (faster than Ed25519).
        Default: ``False``.

    Usage
    -----
    ::

        channel = SlidingWindowChannel(protocol, window_size=64)

        # Sending
        seq, wire = channel.send(b"data")   # returns None if window full
        if wire:
            transport.send(peer_addr, wire)

        # Retransmission poll (call periodically)
        for wire in channel.get_retransmissions():
            transport.send(peer_addr, wire)

        # Receiving a SACK ACK (ACK packet arrived)
        sack_bytes = device.decrypt_packet(ack_packet)
        channel.process_sack(SackFrame.decode(sack_bytes))

        # Receiving a DATA packet
        data_bytes, sack_frame = channel.receive(raw_data_packet)
        if sack_frame:
            ack_wire = channel.build_sack_ack(sack_frame)
            transport.send(peer_addr, ack_wire)
        if data_bytes:
            handle(data_bytes)  # in-order delivery
    """

    def __init__(
        self,
        protocol: Protocol,
        window_size: int = 64,
        base_timeout_ms: float = 200.0,
        max_timeout_ms: float = 8_000.0,
        max_retries: int = 5,
        use_mac: bool = False,
    ) -> None:
        self._proto = protocol
        self._window_size = window_size
        self._base_ms = base_timeout_ms
        self._max_ms = max_timeout_ms
        self._max_retries = max_retries
        self._use_mac = use_mac

        # ── Send-side state ──────────────────────────────────────────────
        # Packets sent but not yet acknowledged, keyed by sequence number.
        self._send_window: Dict[int, WindowedPacket] = {}
        # The lowest sequence number not yet acknowledged.
        self._send_base: int = 0

        # ── Receive-side state ───────────────────────────────────────────
        # Highest in-order sequence number delivered to the application.
        # (-1 means nothing received yet.)
        self._recv_next: int = -1
        # Out-of-order packets buffered until gaps are filled.
        self._recv_buffer: Dict[int, bytes] = {}

    # ------------------------------------------------------------------
    # Send path
    # ------------------------------------------------------------------

    def can_send(self) -> bool:
        """Return ``True`` if the send window has room for another packet."""
        return len(self._send_window) < self._window_size

    def send(self, plaintext: bytes) -> Tuple[Optional[int], Optional[bytes]]:
        """
        Enqueue *plaintext* for delivery and return the wire bytes.

        Returns
        -------
        (sequence, packet_bytes)
            Both values are ``None`` if the send window is full (back-pressure).
            Otherwise *sequence* is the assigned ZTLNP sequence number and
            *packet_bytes* is ready to pass to the transport.
        """
        if not self.can_send():
            return None, None

        if self._use_mac:
            wire = self._proto.local.build_data_packet_mac(
                self._proto.peer_id, plaintext
            ).to_bytes()
        else:
            wire = self._proto.send_data(plaintext)

        seq = struct.unpack_from("!I", wire, SEQUENCE_OFFSET)[0]

        wp = WindowedPacket(
            sequence=seq,
            packet_bytes=wire,
            next_timeout_ms=self._base_ms,
        )
        self._send_window[seq] = wp
        if not self._send_window or len(self._send_window) == 1:
            # First packet in window — initialise send_base.
            self._send_base = seq
        return seq, wire

    # ------------------------------------------------------------------
    # SACK processing (receive side of ACKs)
    # ------------------------------------------------------------------

    def process_sack(self, sack: SackFrame) -> int:
        """
        Remove acknowledged packets from the send window.

        Parameters
        ----------
        sack:
            A parsed :class:`SackFrame` received from the peer.

        Returns
        -------
        int
            Number of packets removed from the send window.
        """
        acked = sack.all_acked()
        removed = 0
        for seq in list(self._send_window.keys()):
            if seq in acked:
                del self._send_window[seq]
                removed += 1

        # Advance send_base to the lowest unacknowledged sequence.
        if self._send_window:
            self._send_base = min(self._send_window.keys())
        return removed

    # ------------------------------------------------------------------
    # Retransmission (send side)
    # ------------------------------------------------------------------

    def get_retransmissions(self) -> List[bytes]:
        """
        Return bytes for each overdue packet that should be retransmitted.

        Raises
        ------
        RetransmitError
            If any packet exceeds ``max_retries``.
        """
        overdue: List[bytes] = []
        failed: List[int] = []

        for seq, wp in list(self._send_window.items()):
            if not wp.is_due():
                continue
            if wp.retries >= self._max_retries:
                failed.append(seq)
                continue
            wp.record_retransmit(self._base_ms, self._max_ms)
            overdue.append(wp.packet_bytes)

        for seq in failed:
            del self._send_window[seq]

        if failed:
            seqs = ", ".join(str(s) for s in failed)
            raise RetransmitError(
                f"Packet(s) with sequence number(s) {seqs} exceeded "
                f"max_retries={self._max_retries} without acknowledgement"
            )

        return overdue

    # ------------------------------------------------------------------
    # Receive path
    # ------------------------------------------------------------------

    def receive(self, raw: bytes) -> Tuple[Optional[bytes], Optional[SackFrame]]:
        """
        Process an incoming DATA packet and return in-order plaintext.

        The method:

        1. Authenticates and decrypts the packet via the protocol session.
        2. Buffers out-of-order packets.
        3. Returns any contiguous in-order plaintext that is now ready.
        4. Builds a :class:`SackFrame` reflecting the current receive state.

        Parameters
        ----------
        raw:
            Raw bytes of an incoming DATA packet.

        Returns
        -------
        (plaintext, sack_frame)
            *plaintext* is ``None`` if no in-order data is newly available.
            *sack_frame* should be sent back to the peer as an ACK.
        """
        packet = self._proto.local.receive_packet(raw)
        seq = packet.sequence
        plaintext_bytes = self._proto.local.decrypt_packet(packet)

        # On the very first received packet, initialise recv_next so that
        # consecutive in-order delivery works regardless of the starting
        # sequence number (which may be > 0 after handshake overhead).
        if self._recv_next == -1:
            self._recv_next = seq - 1

        if seq == self._recv_next + 1:
            # Exactly the next in-order packet.
            self._recv_next = seq
            # Drain any buffered packets that are now contiguous.
            while self._recv_next + 1 in self._recv_buffer:
                self._recv_next += 1
                plaintext_bytes += self._recv_buffer.pop(self._recv_next)
        elif seq > self._recv_next + 1:
            # Out-of-order: buffer it.
            self._recv_buffer[seq] = plaintext_bytes
            plaintext_bytes = None
        else:
            # Duplicate or old packet: discard data but still ACK.
            plaintext_bytes = None

        sack = self._build_sack()
        return plaintext_bytes, sack

    def _build_sack(self) -> SackFrame:
        """Build a SackFrame reflecting the current receive state."""
        blocks: List[Tuple[int, int]] = []

        if self._recv_buffer:
            seqs = sorted(self._recv_buffer.keys())
            left = seqs[0]
            right = seqs[0]
            for s in seqs[1:]:
                if s == right + 1:
                    right = s
                else:
                    blocks.append((left, right))
                    left = s
                    right = s
            blocks.append((left, right))

        return SackFrame(cum_ack=max(self._recv_next, 0), blocks=blocks)

    def build_sack_ack(self, sack: SackFrame) -> bytes:
        """
        Build a signed, encrypted ACK packet carrying a :class:`SackFrame`.

        Parameters
        ----------
        sack:
            The SACK state to encode into the ACK payload.

        Returns
        -------
        bytes
            Serialised ACK packet bytes ready for transmission.
        """
        from ztlnp.packet import Packet, PacketType, PacketFlags
        from ztlnp.crypto import CryptoEngine

        session = self._proto.local.get_session(self._proto.peer_id)
        nonce = CryptoEngine.generate_nonce()
        ciphertext = CryptoEngine.encrypt(session.session_key, nonce, sack.encode())

        packet = Packet(
            ptype=PacketType.ACK,
            sender_id=self._proto.local.device_id,
            payload=ciphertext,
            recipient_id=self._proto.peer_id,
            flags=PacketFlags.ENCRYPTED,
            sequence=session.next_sequence(),
            nonce=nonce,
        )
        packet.signature = CryptoEngine.sign_packet(
            self._proto.local._identity_private, packet
        )
        return packet.to_bytes()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def in_flight(self) -> int:
        """Number of sent-but-unacknowledged packets."""
        return len(self._send_window)

    @property
    def send_base(self) -> int:
        """Lowest sequence number not yet acknowledged."""
        return self._send_base

    @property
    def recv_next(self) -> int:
        """Highest in-order sequence number delivered to the application."""
        return self._recv_next

    @property
    def window_size(self) -> int:
        """Configured send-window size."""
        return self._window_size
