"""
ZTLNP traffic analysis resistance.

Even with perfect encryption, an adversary observing the network can infer
information from:

* **Packet sizes** — variable-length payloads reveal message lengths.
* **Packet timing** — inter-arrival intervals correlate with application
  behaviour and can be used for traffic fingerprinting.
* **Route frequency** — which devices communicate how often.

This module provides three complementary mitigations:

1. **Payload padding** — inflate payloads to a fixed or quantised size so
   that packet lengths reveal nothing about the plaintext length.
2. **Timing jitter** — inject a random delay before transmission to break
   timing correlations between send events.
3. **Cover traffic** — periodically inject dummy encrypted DATA packets so
   that silence intervals do not reveal activity patterns.

All three mechanisms are opt-in and caller-controlled.  None of them modify
the cryptographic security of the underlying protocol.

Padding design
--------------
Padding bytes are appended to the *plaintext* before encryption.  The first
byte of the padding region stores the pad length (0–255 bytes), so the
receiver can strip it deterministically.  This limits padding to 255 bytes
beyond the plaintext; for larger MTUs multiple padding segments could be
chained, but ZTLNP currently limits padding to a single 255-byte segment to
keep the interface simple.

::

    padded_plaintext = original_plaintext + padding_bytes + pad_len_byte(1 B)

The ``PADDING`` flag in the packet header signals to the receiver that the
payload should be stripped after decryption.

Timing jitter
-------------
:func:`jitter_sleep` blocks for a uniformly random duration in
[0, max_jitter_ms] milliseconds.  In performance-sensitive code the caller
may prefer to schedule the send asynchronously; :func:`random_jitter_ms`
returns the chosen delay without sleeping.

Cover traffic
-------------
:class:`CoverTraffic` wraps an established
:class:`~ztlnp.protocol.Protocol` session.  Call
:meth:`~CoverTraffic.maybe_send` periodically; it returns a dummy DATA
packet if enough time has elapsed since the last real or dummy packet,
keeping the observed traffic rate constant.  The dummy payload is random
encrypted bytes indistinguishable from real data.
"""

from __future__ import annotations

import os
import time
from enum import Enum, auto
from typing import Optional, Tuple

from ztlnp.packet import PacketFlags


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------

# Maximum number of padding bytes appended by a single call to pad_to_size().
_MAX_PAD = 255


class PaddingStrategy(Enum):
    """
    How aggressively to pad payloads.

    Attributes
    ----------
    NONE:
        No padding.  Packet sizes directly reflect plaintext lengths.
    FIXED:
        Pad every payload to exactly ``target_size`` bytes.  Packets shorter
        than the target are padded; those already at or above the target are
        not modified.
    RANDOM:
        Add a uniformly random number of bytes in [0, max_pad] to each
        payload.  Provides deniability at the cost of unpredictable overhead.
    BLOCK:
        Round up to the nearest multiple of ``block_size`` bytes.  Leaks
        plaintext length modulo ``block_size``, which is a common trade-off
        between overhead and privacy.
    """

    NONE = auto()
    FIXED = auto()
    RANDOM = auto()
    BLOCK = auto()


def pad_to_size(
    plaintext: bytes,
    strategy: PaddingStrategy = PaddingStrategy.FIXED,
    target_size: int = 256,
    block_size: int = 64,
    max_pad: int = _MAX_PAD,
) -> Tuple[bytes, bool]:
    """
    Append padding to *plaintext* according to *strategy*.

    The last byte of the returned data is always the pad length, so
    :func:`strip_padding` can reconstruct the original plaintext without any
    out-of-band metadata.

    Parameters
    ----------
    plaintext:
        Original bytes to pad.
    strategy:
        One of the :class:`PaddingStrategy` variants.
    target_size:
        Used by ``FIXED`` strategy: pad to this many bytes total (including
        the 1-byte length trailer).
    block_size:
        Used by ``BLOCK`` strategy: round up to a multiple of this value.
    max_pad:
        Used by ``RANDOM`` strategy: maximum padding bytes to add
        (≤ 255).

    Returns
    -------
    (padded_plaintext, was_padded)
        ``was_padded`` is ``True`` if any padding was added.

    Notes
    -----
    If the required pad length would exceed 255, the plaintext is returned
    unmodified (``was_padded=False``).  Callers should size their MTU budgets
    accordingly.
    """
    if strategy == PaddingStrategy.NONE:
        return plaintext, False

    pad_len: int = 0

    if strategy == PaddingStrategy.FIXED:
        needed = target_size - len(plaintext) - 1  # 1 byte for the length
        if needed <= 0 or needed > _MAX_PAD:
            return plaintext, False
        pad_len = needed

    elif strategy == PaddingStrategy.RANDOM:
        effective_max = min(max_pad, _MAX_PAD)
        if effective_max <= 0:
            return plaintext, False
        pad_len = int.from_bytes(os.urandom(1), "big") % (effective_max + 1)
        if pad_len == 0:
            return plaintext, False

    elif strategy == PaddingStrategy.BLOCK:
        remainder = (len(plaintext) + 1) % block_size  # +1 for length byte
        if remainder == 0:
            return plaintext, False
        pad_len = block_size - remainder
        if pad_len > _MAX_PAD:
            return plaintext, False

    padding = os.urandom(pad_len)
    padded = plaintext + padding + bytes([pad_len])
    return padded, True


def strip_padding(padded_plaintext: bytes) -> bytes:
    """
    Remove padding added by :func:`pad_to_size`.

    Reads the last byte as the pad length, removes ``pad_len + 1`` bytes from
    the end, and returns the original plaintext.

    Parameters
    ----------
    padded_plaintext:
        Decrypted bytes including padding and the 1-byte length trailer.

    Returns
    -------
    bytes
        The original plaintext without padding.

    Raises
    ------
    ValueError
        If the data is too short to contain the length byte.
    """
    if len(padded_plaintext) == 0:
        raise ValueError("Cannot strip padding from empty data")
    pad_len = padded_plaintext[-1]
    total_remove = pad_len + 1  # padding bytes + length byte
    if total_remove > len(padded_plaintext):
        raise ValueError(
            f"Padding length byte ({pad_len}) exceeds available data length "
            f"({len(padded_plaintext) - 1})"
        )
    return padded_plaintext[: len(padded_plaintext) - total_remove]


# ---------------------------------------------------------------------------
# Timing jitter
# ---------------------------------------------------------------------------

def random_jitter_ms(max_jitter_ms: float) -> float:
    """
    Return a uniformly random delay in [0, max_jitter_ms) milliseconds.

    The caller can use this value to schedule a delayed send without actually
    blocking.
    """
    if max_jitter_ms <= 0:
        return 0.0
    # Use os.urandom for an unpredictable float rather than random.random()
    # which uses a PRNG seeded from system entropy.
    raw = int.from_bytes(os.urandom(4), "big")
    fraction = raw / 0x100000000
    return fraction * max_jitter_ms


def jitter_sleep(max_jitter_ms: float) -> float:
    """
    Sleep for a random duration in [0, max_jitter_ms) milliseconds.

    Parameters
    ----------
    max_jitter_ms:
        Maximum delay in milliseconds.

    Returns
    -------
    float
        The actual delay applied, in milliseconds.
    """
    delay_ms = random_jitter_ms(max_jitter_ms)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)
    return delay_ms


# ---------------------------------------------------------------------------
# Cover traffic
# ---------------------------------------------------------------------------

class CoverTraffic:
    """
    Generates dummy DATA packets to maintain a constant observed traffic rate.

    An adversary observing the wire can infer when two parties are *not*
    communicating (silence period).  By injecting cover traffic the local
    device keeps the packet rate constant, making activity/silence patterns
    uninformative.

    Parameters
    ----------
    protocol:
        An established :class:`~ztlnp.protocol.Protocol` session.
    interval_ms:
        Minimum interval between cover packets in milliseconds.  If a real
        packet was sent within this window, no cover packet is generated.
        Default: 1 000 ms (1 second).
    cover_payload_size:
        Size of the random plaintext inside each cover packet, in bytes.
        Larger values cost more bandwidth but look more like real traffic.
        Default: 64 bytes.
    use_mac:
        Use the HMAC-SHA-512 fast path for cover packets (lower CPU cost).
        Default: ``True``.

    Usage
    -----
    ::

        cover = CoverTraffic(protocol, interval_ms=500)

        # In a timer callback (e.g. every 100 ms):
        packet_bytes = cover.maybe_send()
        if packet_bytes:
            transport.send(peer_addr, packet_bytes)

        # When a real DATA packet is sent:
        cover.record_real_send()
    """

    def __init__(
        self,
        protocol,               # Protocol
        interval_ms: float = 1_000.0,
        cover_payload_size: int = 64,
        use_mac: bool = True,
    ) -> None:
        self._proto = protocol
        self._interval_ms = interval_ms
        self._cover_size = cover_payload_size
        self._use_mac = use_mac
        self._last_send_ms: float = time.time() * 1000

    def record_real_send(self) -> None:
        """
        Notify the cover-traffic generator that a real packet was just sent.

        Resets the interval timer so a cover packet is not immediately
        injected after real traffic.
        """
        self._last_send_ms = time.time() * 1000

    def maybe_send(self) -> Optional[bytes]:
        """
        Return a cover-traffic packet if the interval has elapsed, else None.

        The returned bytes are a fully serialised, encrypted DATA packet
        containing random plaintext indistinguishable from real application
        data.  The ``PADDING`` flag is **not** set (cover packets look like
        normal data).

        Returns
        -------
        Optional[bytes]
            Serialised packet bytes, or ``None`` if no cover packet is due.
        """
        now_ms = time.time() * 1000
        if now_ms - self._last_send_ms < self._interval_ms:
            return None

        # Build a dummy DATA packet with random plaintext.
        dummy_plaintext = os.urandom(self._cover_size)
        if self._use_mac:
            wire = self._proto.local.build_data_packet_mac(
                self._proto.peer_id, dummy_plaintext
            ).to_bytes()
        else:
            wire = self._proto.send_data(dummy_plaintext)

        self._last_send_ms = now_ms
        return wire

    @property
    def interval_ms(self) -> float:
        """Target cover-traffic interval in milliseconds."""
        return self._interval_ms

    @interval_ms.setter
    def interval_ms(self, value: float) -> None:
        if value <= 0:
            raise ValueError("interval_ms must be positive")
        self._interval_ms = value
