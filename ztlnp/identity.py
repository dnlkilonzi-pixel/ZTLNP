"""
ZTLNP forward-secure identity rotation.

Background
----------
A long-lived Ed25519 identity key is a single point of failure: if the private
key is compromised, an attacker can impersonate the device indefinitely.
Forward-secure identity rotation mitigates this by allowing a device to
**publicly commit** to a new key while preserving the trust chain built up
with the old one.

Protocol
--------
When a device rotates its identity key it produces a :class:`KeyTransition`
blob signed by the **old** private key.  Peers that already trust the old
device identity can verify the transition and transfer that trust to the new
identity without any out-of-band interaction.

Transition blob wire format (128 bytes body + 64 bytes old-key signature)
==========================================================================

::

    [old_device_id  (32 B)]   SHA-256 of the old Ed25519 public key
    [new_device_id  (32 B)]   SHA-256 of the new Ed25519 public key
    [new_ed25519_pub(32 B)]   New Ed25519 public key (raw 32 bytes)
    [timestamp_ms   ( 8 B)]   Milliseconds since Unix epoch (big-endian uint64)
    ────────────────────── total body: 104 bytes
    [old_key_sig    (64 B)]   Ed25519 signature of the 104-byte body
                              using the OLD private key
    ────────────────────── total: 168 bytes

The receiver MUST verify:

1. ``old_device_id`` matches the identity it already trusts.
2. ``new_device_id == SHA-256(new_ed25519_pub)``.
3. ``old_key_sig`` verifies against the stored *old* public key.
4. ``timestamp_ms`` is not in the future (clock skew tolerance: 30 s) and
   is newer than the last rotation timestamp stored for this device.
5. The transition has not been seen before (replay prevention).

Trust chain preservation
------------------------
After a successful transition the peer:

* Stores the new key at the **same trust level** as the old key (not
  downgraded to TOFU).
* Retires the old device ID (no longer accepts packets signed with it).
* Records the transition in a history log so auditors can trace the chain.

Sybil note
----------
Unlimited rotation could enable a Sybil attack (create many keys, each
endorsed by the last).  To limit this, :class:`TrustStore` accepts a
``max_rotations`` parameter (default 10).  Once exhausted the device must
obtain a fresh endorsement from a VERIFIED peer.
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ztlnp.crypto import CryptoEngine
from ztlnp.exceptions import KeyRotationError


# ---------------------------------------------------------------------------
# Wire-format constants
# ---------------------------------------------------------------------------

_BODY_FMT = "!32s32s32sQ"          # old_id, new_id, new_pub, timestamp_ms
_BODY_SIZE = struct.calcsize(_BODY_FMT)  # 104 bytes
_SIG_SIZE = 64                      # Ed25519 signature
TRANSITION_SIZE = _BODY_SIZE + _SIG_SIZE  # 168 bytes total

_MAX_CLOCK_SKEW_MS = 30_000         # 30 seconds


# ---------------------------------------------------------------------------
# Key transition dataclass
# ---------------------------------------------------------------------------

@dataclass
class KeyTransition:
    """
    A signed announcement that a device is rotating its identity key.

    Parameters
    ----------
    old_device_id:
        32-byte identity of the device *before* rotation (SHA-256 of old pub).
    new_device_id:
        32-byte identity of the device *after* rotation (SHA-256 of new pub).
    new_ed25519_public:
        Raw 32-byte new Ed25519 public key.
    timestamp_ms:
        Milliseconds since Unix epoch when the transition was created.
    signature:
        64-byte Ed25519 signature of the body, made with the **old** key.
    """

    old_device_id: bytes
    new_device_id: bytes
    new_ed25519_public: bytes
    timestamp_ms: int
    signature: bytes

    def __post_init__(self) -> None:
        if len(self.old_device_id) != 32:
            raise ValueError("old_device_id must be 32 bytes")
        if len(self.new_device_id) != 32:
            raise ValueError("new_device_id must be 32 bytes")
        if len(self.new_ed25519_public) != 32:
            raise ValueError("new_ed25519_public must be 32 bytes")
        if len(self.signature) != _SIG_SIZE:
            raise ValueError(f"signature must be {_SIG_SIZE} bytes")

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _body_bytes(self) -> bytes:
        return struct.pack(
            _BODY_FMT,
            self.old_device_id,
            self.new_device_id,
            self.new_ed25519_public,
            self.timestamp_ms,
        )

    def to_bytes(self) -> bytes:
        """Serialise to a 168-byte blob."""
        return self._body_bytes() + self.signature

    @classmethod
    def from_bytes(cls, data: bytes) -> "KeyTransition":
        """
        Deserialise from a 168-byte blob.

        Raises
        ------
        KeyRotationError
            If the data is the wrong length or structurally invalid.
        """
        if len(data) != TRANSITION_SIZE:
            raise KeyRotationError(
                f"KeyTransition blob must be {TRANSITION_SIZE} bytes, got {len(data)}"
            )
        old_device_id, new_device_id, new_pub, ts = struct.unpack_from(_BODY_FMT, data)
        sig = data[_BODY_SIZE:]
        return cls(
            old_device_id=old_device_id,
            new_device_id=new_device_id,
            new_ed25519_public=new_pub,
            timestamp_ms=ts,
            signature=sig,
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def create_key_transition(
    old_private_key,          # Ed25519PrivateKey
    old_device_id: bytes,
    new_ed25519_public: bytes,
) -> KeyTransition:
    """
    Create and sign a :class:`KeyTransition` using the *old* private key.

    Parameters
    ----------
    old_private_key:
        Ed25519 private key that is being retired.
    old_device_id:
        32-byte identity of the old key (SHA-256 of its public key bytes).
    new_ed25519_public:
        Raw 32-byte Ed25519 public key to transition to.

    Returns
    -------
    KeyTransition
        A fully signed transition ready to distribute to peers.
    """
    new_device_id = hashlib.sha256(new_ed25519_public).digest()
    ts = int(time.time() * 1000)

    body = struct.pack(_BODY_FMT, old_device_id, new_device_id, new_ed25519_public, ts)
    sig = CryptoEngine.sign(old_private_key, body)

    return KeyTransition(
        old_device_id=old_device_id,
        new_device_id=new_device_id,
        new_ed25519_public=new_ed25519_public,
        timestamp_ms=ts,
        signature=sig,
    )


# ---------------------------------------------------------------------------
# Rotation history (per device)
# ---------------------------------------------------------------------------

@dataclass
class RotationRecord:
    """
    Historical record of a completed key rotation.

    Parameters
    ----------
    old_device_id:
        The retired 32-byte device identity.
    new_device_id:
        The new 32-byte device identity.
    timestamp_ms:
        Milliseconds since epoch when the rotation was applied.
    """

    old_device_id: bytes
    new_device_id: bytes
    timestamp_ms: int


# ---------------------------------------------------------------------------
# RotationManager: validates and applies transitions to a TrustStore
# ---------------------------------------------------------------------------

class RotationManager:
    """
    Applies and tracks forward-secure identity key rotations.

    A :class:`RotationManager` is a companion to a
    :class:`~ztlnp.trust.TrustStore`.  It validates incoming
    :class:`KeyTransition` blobs and, if valid, migrates the trust record for
    the rotating device to its new identity.

    Parameters
    ----------
    trust_store:
        The :class:`~ztlnp.trust.TrustStore` to update on successful rotations.
    max_rotations:
        Maximum number of rotations a single identity chain may perform before
        a fresh out-of-band verification is required.  Limits Sybil-via-rotation
        attacks.  Default: 10.
    """

    def __init__(self, trust_store, max_rotations: int = 10) -> None:
        self._store = trust_store
        self._max_rotations = max_rotations

        # Maps old_device_id → new_device_id for retired keys.
        # Used to redirect packets for legacy IDs to the current identity.
        self._retired: Dict[bytes, bytes] = {}

        # Maps current_device_id → list[RotationRecord] (full history).
        self._history: Dict[bytes, List[RotationRecord]] = {}

        # Maps current_device_id → int (rotation count in this chain).
        self._rotation_count: Dict[bytes, int] = {}

        # Tracks timestamps to reject replays: old_device_id → last ts.
        self._last_ts: Dict[bytes, int] = {}

    def apply_transition(self, transition: KeyTransition) -> None:
        """
        Validate a :class:`KeyTransition` and migrate the trust record.

        On success the trust store will contain a record for
        ``transition.new_device_id`` at the same (or higher) trust level as
        the old one, and the old record will be marked as retired.

        Parameters
        ----------
        transition:
            The transition to apply.

        Raises
        ------
        KeyRotationError
            If any validation step fails:

            * Old device unknown in the trust store.
            * Signature invalid.
            * Timestamp out of range or older than the last seen timestamp.
            * new_device_id does not match SHA-256(new_ed25519_public).
            * Rotation count would exceed max_rotations.
        """
        from ztlnp.trust import TrustLevel

        old_id = transition.old_device_id
        new_id = transition.new_device_id

        # 1 — Old identity must be known and trusted.
        old_record = self._store.get(old_id)
        if old_record is None:
            raise KeyRotationError(
                f"Unknown old device {old_id.hex()} — cannot apply transition"
            )

        # 2 — Verify new_device_id matches the new public key.
        expected_new_id = hashlib.sha256(transition.new_ed25519_public).digest()
        if new_id != expected_new_id:
            raise KeyRotationError(
                "new_device_id does not match SHA-256(new_ed25519_public)"
            )

        # 3 — Timestamp sanity: not too far in the future, not a replay.
        now_ms = int(time.time() * 1000)
        if transition.timestamp_ms > now_ms + _MAX_CLOCK_SKEW_MS:
            raise KeyRotationError(
                f"KeyTransition timestamp {transition.timestamp_ms} ms is in the future"
            )
        last_ts = self._last_ts.get(old_id, 0)
        if transition.timestamp_ms <= last_ts:
            raise KeyRotationError(
                f"KeyTransition timestamp {transition.timestamp_ms} ms is not newer "
                f"than last seen ({last_ts} ms) — possible replay"
            )

        # 4 — Verify signature with the OLD public key.
        body = transition._body_bytes()
        if not CryptoEngine.verify(old_record.ed25519_public, body, transition.signature):
            raise KeyRotationError("KeyTransition signature verification failed")

        # 5 — Rotation count limit.
        count = self._rotation_count.get(old_id, 0)
        if count >= self._max_rotations:
            raise KeyRotationError(
                f"Device {old_id.hex()} has exhausted its rotation budget "
                f"(max_rotations={self._max_rotations})"
            )

        # ── All checks passed — migrate trust ──

        # Add/upgrade new identity at the same trust level as the old one.
        self._store.add(transition.new_ed25519_public, old_record.trust_level)
        new_record = self._store.get(new_id)

        # Carry over endorsers.
        for endorser_id in old_record.endorsers:
            if endorser_id not in new_record.endorsers:
                new_record.endorsers.append(endorser_id)

        # Record retirement.
        self._retired[old_id] = new_id
        self._last_ts[old_id] = transition.timestamp_ms

        # Update rotation count for the new identity (inherits old chain length+1).
        chain_count = count + 1
        self._rotation_count[new_id] = chain_count

        # History.
        rec = RotationRecord(
            old_device_id=old_id,
            new_device_id=new_id,
            timestamp_ms=transition.timestamp_ms,
        )
        self._history.setdefault(new_id, []).append(rec)

    def resolve(self, device_id: bytes) -> bytes:
        """
        Follow the retirement chain to find the *current* device identity.

        If *device_id* has been retired one or more times, the most recent
        active identity is returned.  If it has not been retired, *device_id*
        itself is returned.

        Parameters
        ----------
        device_id:
            Any device ID (current or historical).
        """
        current = device_id
        visited = set()
        while current in self._retired:
            if current in visited:
                break  # Guard against accidental cycles.
            visited.add(current)
            current = self._retired[current]
        return current

    def is_retired(self, device_id: bytes) -> bool:
        """Return ``True`` if *device_id* has been superseded by a rotation."""
        return device_id in self._retired

    def rotation_history(self, device_id: bytes) -> List[RotationRecord]:
        """
        Return the full rotation history for *device_id* (current identity).

        Each :class:`RotationRecord` describes one completed rotation step.
        """
        return list(self._history.get(device_id, []))

    def rotation_count(self, device_id: bytes) -> int:
        """Return how many rotations *device_id*'s chain has performed."""
        return self._rotation_count.get(device_id, 0)
