"""
ZTLNP wire-format packet definition.

Wire layout (all multi-byte integers are big-endian):

 Offset  Length  Field
 ------  ------  -----
      0       4  Magic           b"ZTLP"
      4       1  Version         0x01
      5       1  Type            see PacketType
      6       2  Flags           see PacketFlags
      8      32  Sender ID       SHA-256 of sender's Ed25519 public key
     40      32  Recipient ID    SHA-256 of recipient's Ed25519 public key
                                 (all-zeros means broadcast)
     72       8  Timestamp       milliseconds since Unix epoch (big-endian)
     80       4  Sequence Num    monotonically increasing per sender (big-endian)
     84      12  Nonce           AES-256-GCM nonce (random per packet)
     96       4  Payload Length  number of bytes that follow (big-endian)
    100       N  Payload         AES-256-GCM ciphertext (or plaintext for HELLO)
  100+N      64  Signature       Ed25519 signature over bytes [0 .. 100+N)

HELLO packets carry unencrypted payload so that peers can bootstrap a shared
secret before any session key exists.  All other packet types carry encrypted
payloads.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum

MAGIC: bytes = b"ZTLP"
VERSION: int = 0x01

# Fixed-size header fields (before the variable-length payload and signature).
_HEADER_FMT = "!4sBBH32s32sQI12sI"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)  # 100 bytes
_SIG_SIZE = 64  # Ed25519 signature
BROADCAST_ID: bytes = b"\x00" * 32


class PacketType(IntEnum):
    HELLO = 0x01            # Advertise identity + ephemeral public key
    KEY_EXCHANGE = 0x02     # Confirm derived session key
    DATA = 0x03             # Encrypted application data
    ACK = 0x04              # Acknowledge a DATA or KEY_EXCHANGE packet
    ERROR = 0x05            # Signal a protocol error to the peer
    BYE = 0x06              # Graceful session teardown
    ROUTE_ANNOUNCE = 0x07   # Mesh: advertise reachable device IDs
    TRUST_ENDORSE = 0x08    # Web-of-trust: signed endorsement of a peer
    KEY_ROTATE = 0x09       # Forward-secure identity key rotation


class PacketFlags(IntEnum):
    NONE = 0x0000
    ENCRYPTED = 0x0001   # Payload is AES-256-GCM ciphertext
    BROADCAST = 0x0002   # Addressed to all peers (recipient_id is all-zeros)
    MAC_AUTH = 0x0004    # Signature field carries HMAC-SHA-512 (not Ed25519)
    PADDING = 0x0008     # Payload contains trailing padding bytes (privacy)


@dataclass
class Packet:
    """
    A ZTLNP packet.

    Parameters
    ----------
    ptype:
        One of the ``PacketType`` values.
    sender_id:
        32-byte device identifier (SHA-256 of the sender's Ed25519 public key).
    payload:
        Raw bytes — either plaintext (HELLO) or AES-256-GCM ciphertext.
    recipient_id:
        32-byte device identifier of the intended recipient.  Defaults to
        ``BROADCAST_ID`` (all-zeros).
    flags:
        Bitmask of ``PacketFlags`` values.
    sequence:
        Monotonically increasing 32-bit sequence number assigned by the caller.
    nonce:
        12-byte AES-GCM nonce; generated fresh for every packet.
    timestamp_ms:
        Milliseconds since the Unix epoch; auto-populated if zero.
    signature:
        64-byte Ed25519 signature appended after serialisation.
    """

    ptype: PacketType
    sender_id: bytes
    payload: bytes
    recipient_id: bytes = field(default_factory=lambda: BROADCAST_ID)
    flags: int = PacketFlags.NONE
    sequence: int = 0
    nonce: bytes = field(default_factory=lambda: b"\x00" * 12)
    timestamp_ms: int = 0
    signature: bytes = field(default_factory=lambda: b"\x00" * _SIG_SIZE)

    def __post_init__(self) -> None:
        if len(self.sender_id) != 32:
            raise ValueError("sender_id must be exactly 32 bytes")
        if len(self.recipient_id) != 32:
            raise ValueError("recipient_id must be exactly 32 bytes")
        if len(self.nonce) != 12:
            raise ValueError("nonce must be exactly 12 bytes")
        if self.timestamp_ms == 0:
            self.timestamp_ms = _now_ms()

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def header_bytes(self) -> bytes:
        """Return the fixed-size header (100 bytes), without payload or sig."""
        return struct.pack(
            _HEADER_FMT,
            MAGIC,
            VERSION,
            int(self.ptype),
            self.flags,
            self.sender_id,
            self.recipient_id,
            self.timestamp_ms,
            self.sequence,
            self.nonce,
            len(self.payload),
        )

    def signed_bytes(self) -> bytes:
        """Return all bytes that are covered by the Ed25519 signature."""
        return self.header_bytes() + self.payload

    def to_bytes(self) -> bytes:
        """Serialise the complete packet (header + payload + signature)."""
        return self.signed_bytes() + self.signature

    @classmethod
    def from_bytes(cls, data: bytes) -> "Packet":
        """
        Deserialise a packet from raw bytes.

        Raises
        ------
        InvalidMagicError
            If the first four bytes are not ``b"ZTLP"``.
        InvalidVersionError
            If the version field is not ``0x01``.
        ValueError
            If the data is too short or the payload/signature are truncated.
        """
        from ztlnp.exceptions import InvalidMagicError, InvalidVersionError

        if len(data) < _HEADER_SIZE + _SIG_SIZE:
            raise ValueError(
                f"Packet too short: need at least {_HEADER_SIZE + _SIG_SIZE} bytes, "
                f"got {len(data)}"
            )

        (
            magic,
            version,
            ptype_raw,
            flags,
            sender_id,
            recipient_id,
            timestamp_ms,
            sequence,
            nonce,
            payload_len,
        ) = struct.unpack_from(_HEADER_FMT, data, 0)

        if magic != MAGIC:
            raise InvalidMagicError(f"Expected magic {MAGIC!r}, got {magic!r}")
        if version != VERSION:
            raise InvalidVersionError(
                f"Unsupported version 0x{version:02x} (expected 0x{VERSION:02x})"
            )

        expected_total = _HEADER_SIZE + payload_len + _SIG_SIZE
        if len(data) < expected_total:
            raise ValueError(
                f"Packet truncated: expected {expected_total} bytes, got {len(data)}"
            )

        payload = data[_HEADER_SIZE : _HEADER_SIZE + payload_len]
        signature = data[_HEADER_SIZE + payload_len : _HEADER_SIZE + payload_len + _SIG_SIZE]

        return cls(
            ptype=PacketType(ptype_raw),
            sender_id=sender_id,
            payload=payload,
            recipient_id=recipient_id,
            flags=flags,
            sequence=sequence,
            nonce=nonce,
            timestamp_ms=timestamp_ms,
            signature=signature,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    """Current time in milliseconds since the Unix epoch."""
    return int(time.time() * 1000)
