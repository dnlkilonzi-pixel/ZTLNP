"""
ZTLNP reliability layer — retransmission and flow control.

The base ZTLNP protocol is datagram-oriented (like UDP): packets may be lost,
reordered, or duplicated.  The :class:`ReliableChannel` wraps a
:class:`~ztlnp.protocol.Protocol` session to add:

* **Stop-and-wait ARQ** — the sender holds each DATA packet until an ACK is
  received (or the packet is retransmitted up to ``max_retries`` times).
* **Exponential backoff** — retransmission intervals double on each retry,
  starting from ``base_timeout_ms`` and capped at ``max_timeout_ms``.
* **Pending-packet queue** — packets that have been sent but not yet
  acknowledged are kept in a dictionary keyed by sequence number.  Call
  :meth:`get_retransmissions` periodically (e.g. in a background thread) to
  retrieve packets that need to be re-sent.
* **ACK processing** — call :meth:`process_ack` when an ACK packet arrives to
  retire the corresponding pending entry.

Usage
-----
::

    channel = ReliableChannel(protocol, base_timeout_ms=500, max_retries=4)

    # Send side
    seq, wire = channel.send(b"important message")
    transport.send(peer_addr, wire)   # transmit immediately

    # Later in a timer callback
    for retransmit_wire in channel.get_retransmissions():
        transport.send(peer_addr, retransmit_wire)

    # Receive side (when an ACK packet arrives)
    ack_packet = Packet.from_bytes(raw_ack)
    acked_seq = struct.unpack("!I", device.decrypt_packet(ack_packet))[0]
    channel.process_ack(acked_seq)

Notes
-----
* :class:`ReliableChannel` does **not** spawn any threads itself.  The caller
  decides when to poll :meth:`get_retransmissions` and how to drive I/O.
  This keeps the class simple, testable, and free of hidden concurrency.
* :meth:`get_retransmissions` raises :class:`~ztlnp.exceptions.RetransmitError`
  for any packet that has exceeded ``max_retries``.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ztlnp.exceptions import RetransmitError
from ztlnp.packet import SEQUENCE_OFFSET
from ztlnp.protocol import Protocol


# ---------------------------------------------------------------------------
# Pending packet record
# ---------------------------------------------------------------------------

@dataclass
class PendingPacket:
    """
    A DATA packet that has been sent but not yet acknowledged.

    Parameters
    ----------
    sequence:
        The ZTLNP sequence number assigned to the packet.
    packet_bytes:
        Serialised packet bytes, ready to retransmit.
    sent_at:
        Unix timestamp (float) of the most recent transmission.
    retries:
        Number of retransmissions so far (0 = not yet retried).
    next_timeout_ms:
        The timeout (ms) that governs when the *next* retransmission is due.
        Doubles on each retry (exponential backoff).
    """

    sequence: int
    packet_bytes: bytes
    sent_at: float = field(default_factory=time.time)
    retries: int = 0
    next_timeout_ms: float = 500.0

    def is_due(self) -> bool:
        """Return ``True`` if the retransmit deadline has passed."""
        return (time.time() - self.sent_at) * 1000 >= self.next_timeout_ms

    def record_retransmit(self, base_timeout_ms: float, max_timeout_ms: float) -> None:
        """Update internal state after a retransmission has been performed."""
        self.retries += 1
        self.sent_at = time.time()
        self.next_timeout_ms = min(self.next_timeout_ms * 2, max_timeout_ms)


# ---------------------------------------------------------------------------
# Reliable channel
# ---------------------------------------------------------------------------

class ReliableChannel:
    """
    Stop-and-wait ARQ channel on top of a ZTLNP :class:`~ztlnp.protocol.Protocol`.

    Parameters
    ----------
    protocol:
        An *established* protocol session.
    base_timeout_ms:
        Initial retransmission timeout in milliseconds.  Default: 500 ms.
    max_timeout_ms:
        Maximum retransmission timeout (after exponential backoff) in
        milliseconds.  Default: 16 000 ms (16 seconds).
    max_retries:
        Maximum number of retransmissions per packet before
        :class:`~ztlnp.exceptions.RetransmitError` is raised.  Default: 5.
    use_mac:
        If ``True``, build DATA packets using the fast MAC_AUTH path
        (:meth:`~ztlnp.device.Device.build_data_packet_mac`) instead of
        full Ed25519 signing.  Default: ``False``.
    """

    def __init__(
        self,
        protocol: Protocol,
        base_timeout_ms: float = 500.0,
        max_timeout_ms: float = 16_000.0,
        max_retries: int = 5,
        use_mac: bool = False,
    ) -> None:
        self._proto = protocol
        self._base_timeout_ms = base_timeout_ms
        self._max_timeout_ms = max_timeout_ms
        self._max_retries = max_retries
        self._use_mac = use_mac
        self._pending: Dict[int, PendingPacket] = {}

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def send(self, plaintext: bytes) -> Tuple[int, bytes]:
        """
        Build an encrypted DATA packet for *plaintext* and register it as
        pending acknowledgement.

        Parameters
        ----------
        plaintext:
            Application data to send.

        Returns
        -------
        (sequence, packet_bytes)
            ``sequence`` is the ZTLNP sequence number; ``packet_bytes`` is the
            serialised packet ready to transmit.

        Notes
        -----
        This method does *not* transmit anything.  The caller is responsible
        for passing ``packet_bytes`` to the appropriate transport.
        """
        if self._use_mac:
            wire = self._proto.local.build_data_packet_mac(
                self._proto.peer_id, plaintext
            ).to_bytes()
        else:
            wire = self._proto.send_data(plaintext)

        # Extract the sequence number from the wire bytes (offset 80, 4 bytes).
        seq = struct.unpack_from("!I", wire, SEQUENCE_OFFSET)[0]

        pending = PendingPacket(
            sequence=seq,
            packet_bytes=wire,
            next_timeout_ms=self._base_timeout_ms,
        )
        self._pending[seq] = pending
        return seq, wire

    # ------------------------------------------------------------------
    # ACK processing
    # ------------------------------------------------------------------

    def process_ack(self, sequence: int) -> bool:
        """
        Mark *sequence* as acknowledged, removing it from the pending queue.

        Parameters
        ----------
        sequence:
            The sequence number carried in the ACK packet's payload.

        Returns
        -------
        bool
            ``True`` if the sequence was in the pending queue and was removed;
            ``False`` if it was not found (e.g. duplicate ACK).
        """
        return self._pending.pop(sequence, None) is not None

    # ------------------------------------------------------------------
    # Retransmission
    # ------------------------------------------------------------------

    def get_retransmissions(self) -> List[bytes]:
        """
        Return a list of packet bytes that are overdue for retransmission.

        Call this method periodically (e.g. every 100 ms) and re-send each
        returned item on the appropriate transport.

        Raises
        ------
        RetransmitError
            If any pending packet has exceeded ``max_retries``.  The packet is
            removed from the pending queue before the exception is raised so
            that other pending packets can still be retransmitted.
        """
        overdue: List[bytes] = []
        failed: List[int] = []

        for seq, pending in list(self._pending.items()):
            if not pending.is_due():
                continue
            if pending.retries >= self._max_retries:
                failed.append(seq)
                continue
            pending.record_retransmit(self._base_timeout_ms, self._max_timeout_ms)
            overdue.append(pending.packet_bytes)

        for seq in failed:
            del self._pending[seq]

        if failed:
            seqs = ", ".join(str(s) for s in failed)
            raise RetransmitError(
                f"Packet(s) with sequence number(s) {seqs} exceeded "
                f"max_retries={self._max_retries} without acknowledgement"
            )

        return overdue

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def pending_count(self) -> int:
        """Number of packets awaiting acknowledgement."""
        return len(self._pending)

    @property
    def pending_sequences(self) -> List[int]:
        """Sequence numbers of packets awaiting acknowledgement."""
        return sorted(self._pending.keys())
