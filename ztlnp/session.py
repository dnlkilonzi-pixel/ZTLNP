"""
ZTLNP session: shared state between two authenticated peers.

A ``Session`` is created once an X25519 key exchange has completed.  It holds:

- the derived AES-256-GCM session key,
- the peer's Ed25519 public key (used to verify every incoming packet),
- per-direction sequence-number and replay-window state.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Set

# Maximum clock skew we accept between two devices (milliseconds).
MAX_CLOCK_SKEW_MS: int = 30_000  # 30 seconds

# Size of the sequence-number replay window.
_REPLAY_WINDOW: int = 64


@dataclass
class Session:
    """
    Symmetric session state shared by two ZTLNP peers.

    Parameters
    ----------
    peer_id:
        32-byte device identifier of the remote peer.
    peer_ed25519_public:
        32-byte raw Ed25519 public key of the remote peer.  Every incoming
        packet is verified against this key (control-plane packets and any
        packet without the MAC_AUTH flag).
    session_key:
        32-byte AES-256-GCM key derived from the X25519 exchange.
    mac_key:
        64-byte HMAC-SHA-512 key derived from the same X25519 exchange with a
        different HKDF info string.  Used for the MAC_AUTH fast-path on DATA
        packets (replaces Ed25519 per-packet signing, ~10–40× faster).
    local_sequence:
        Next sequence number to assign to outgoing packets (auto-incremented).
    """

    peer_id: bytes
    peer_ed25519_public: bytes
    session_key: bytes
    mac_key: bytes
    local_sequence: int = 0

    # Highest sequence number seen from the peer and a window of recent ones.
    _peer_max_seq: int = field(default=0, init=False, repr=False)
    _peer_seq_window: Set[int] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        if len(self.peer_id) != 32:
            raise ValueError("peer_id must be 32 bytes")
        if len(self.peer_ed25519_public) != 32:
            raise ValueError("peer_ed25519_public must be 32 bytes")
        if len(self.session_key) != 32:
            raise ValueError("session_key must be 32 bytes")
        if len(self.mac_key) != 64:
            raise ValueError("mac_key must be 64 bytes")

    # ------------------------------------------------------------------
    # Outgoing helpers
    # ------------------------------------------------------------------

    def next_sequence(self) -> int:
        """Return the next outgoing sequence number and advance the counter."""
        seq = self.local_sequence
        self.local_sequence += 1
        return seq

    # ------------------------------------------------------------------
    # Replay-attack prevention
    # ------------------------------------------------------------------

    def check_replay(self, sequence: int, timestamp_ms: int) -> None:
        """
        Validate *sequence* and *timestamp_ms* from an incoming packet.

        Raises
        ------
        ReplayAttackError
            If the packet appears to be a replay or its timestamp is outside
            the allowed clock-skew window.
        """
        from ztlnp.exceptions import ReplayAttackError

        now_ms = int(time.time() * 1000)
        if abs(now_ms - timestamp_ms) > MAX_CLOCK_SKEW_MS:
            raise ReplayAttackError(
                f"Packet timestamp {timestamp_ms} ms is outside the "
                f"{MAX_CLOCK_SKEW_MS} ms clock-skew window"
            )

        if sequence in self._peer_seq_window:
            raise ReplayAttackError(
                f"Duplicate sequence number {sequence} detected (replay attack)"
            )

        # Accept packets that are within the replay window even if they arrive
        # slightly out of order (e.g. due to network reordering).
        if sequence <= self._peer_max_seq - _REPLAY_WINDOW:
            raise ReplayAttackError(
                f"Sequence number {sequence} is too far below the current "
                f"maximum ({self._peer_max_seq})"
            )

        # Record the sequence number and advance the window.
        self._peer_seq_window.add(sequence)
        if sequence > self._peer_max_seq:
            self._peer_max_seq = sequence
            # Prune old entries outside the window.
            self._peer_seq_window = {
                s for s in self._peer_seq_window if s > self._peer_max_seq - _REPLAY_WINDOW
            }
