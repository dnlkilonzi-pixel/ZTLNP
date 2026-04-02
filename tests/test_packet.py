"""
Tests for the ZTLNP packet format: serialisation, deserialisation, and wire
layout invariants.
"""

import struct
import pytest

from ztlnp.packet import (
    Packet,
    PacketType,
    PacketFlags,
    MAGIC,
    VERSION,
    BROADCAST_ID,
    _HEADER_SIZE,
    _SIG_SIZE,
)
from ztlnp.exceptions import InvalidMagicError, InvalidVersionError


SENDER_ID = b"\x01" * 32
RECIPIENT_ID = b"\x02" * 32
NONCE = b"\x03" * 12
SIG = b"\x04" * 64


# ---------------------------------------------------------------------------
# Basic construction
# ---------------------------------------------------------------------------

class TestPacketConstruction:
    def test_defaults(self):
        p = Packet(ptype=PacketType.DATA, sender_id=SENDER_ID, payload=b"hello")
        assert p.recipient_id == BROADCAST_ID
        assert p.flags == PacketFlags.NONE
        assert p.sequence == 0
        assert len(p.nonce) == 12
        assert len(p.signature) == 64
        assert p.timestamp_ms > 0

    def test_explicit_fields(self):
        p = Packet(
            ptype=PacketType.DATA,
            sender_id=SENDER_ID,
            payload=b"abc",
            recipient_id=RECIPIENT_ID,
            flags=PacketFlags.ENCRYPTED,
            sequence=42,
            nonce=NONCE,
            timestamp_ms=1_000_000,
        )
        assert p.recipient_id == RECIPIENT_ID
        assert p.flags == PacketFlags.ENCRYPTED
        assert p.sequence == 42
        assert p.nonce == NONCE
        assert p.timestamp_ms == 1_000_000

    def test_invalid_sender_id_length(self):
        with pytest.raises(ValueError, match="sender_id"):
            Packet(ptype=PacketType.DATA, sender_id=b"\x01" * 31, payload=b"")

    def test_invalid_recipient_id_length(self):
        with pytest.raises(ValueError, match="recipient_id"):
            Packet(
                ptype=PacketType.DATA,
                sender_id=SENDER_ID,
                payload=b"",
                recipient_id=b"\x02" * 33,
            )

    def test_invalid_nonce_length(self):
        with pytest.raises(ValueError, match="nonce"):
            Packet(
                ptype=PacketType.DATA,
                sender_id=SENDER_ID,
                payload=b"",
                nonce=b"\x00" * 11,
            )


# ---------------------------------------------------------------------------
# Serialisation / deserialisation round-trip
# ---------------------------------------------------------------------------

class TestPacketRoundTrip:
    def _make_packet(self, payload: bytes = b"test payload") -> Packet:
        return Packet(
            ptype=PacketType.DATA,
            sender_id=SENDER_ID,
            payload=payload,
            recipient_id=RECIPIENT_ID,
            flags=PacketFlags.ENCRYPTED,
            sequence=7,
            nonce=NONCE,
            timestamp_ms=999_999,
            signature=SIG,
        )

    def test_serialise_length(self):
        p = self._make_packet(b"hello")
        wire = p.to_bytes()
        assert len(wire) == _HEADER_SIZE + len(b"hello") + _SIG_SIZE

    def test_round_trip_empty_payload(self):
        p = self._make_packet(b"")
        recovered = Packet.from_bytes(p.to_bytes())
        assert recovered.payload == b""
        assert recovered.ptype == PacketType.DATA
        assert recovered.sender_id == SENDER_ID

    def test_round_trip_nonempty_payload(self):
        payload = b"zero-trust packet payload"
        p = self._make_packet(payload)
        recovered = Packet.from_bytes(p.to_bytes())
        assert recovered.payload == payload
        assert recovered.sequence == 7
        assert recovered.flags == PacketFlags.ENCRYPTED
        assert recovered.nonce == NONCE
        assert recovered.timestamp_ms == 999_999
        assert recovered.signature == SIG
        assert recovered.recipient_id == RECIPIENT_ID

    def test_all_packet_types_round_trip(self):
        for ptype in PacketType:
            p = Packet(
                ptype=ptype,
                sender_id=SENDER_ID,
                payload=b"x",
                timestamp_ms=1,
                signature=SIG,
            )
            recovered = Packet.from_bytes(p.to_bytes())
            assert recovered.ptype == ptype


# ---------------------------------------------------------------------------
# Wire-format validation
# ---------------------------------------------------------------------------

class TestPacketWireFormat:
    def test_magic_in_wire_bytes(self):
        p = Packet(ptype=PacketType.HELLO, sender_id=SENDER_ID, payload=b"")
        assert p.to_bytes()[:4] == MAGIC

    def test_version_in_wire_bytes(self):
        p = Packet(ptype=PacketType.HELLO, sender_id=SENDER_ID, payload=b"")
        assert p.to_bytes()[4] == VERSION

    def test_type_byte_position(self):
        p = Packet(ptype=PacketType.ACK, sender_id=SENDER_ID, payload=b"", signature=SIG)
        assert p.to_bytes()[5] == int(PacketType.ACK)

    def test_signed_bytes_excludes_signature(self):
        p = Packet(
            ptype=PacketType.DATA,
            sender_id=SENDER_ID,
            payload=b"abc",
            signature=SIG,
        )
        wire = p.to_bytes()
        signed = p.signed_bytes()
        assert wire == signed + SIG
        assert len(signed) == len(wire) - _SIG_SIZE


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestPacketErrors:
    def test_bad_magic(self):
        p = Packet(ptype=PacketType.DATA, sender_id=SENDER_ID, payload=b"x", signature=SIG)
        raw = bytearray(p.to_bytes())
        raw[:4] = b"XXXX"
        with pytest.raises(InvalidMagicError):
            Packet.from_bytes(bytes(raw))

    def test_bad_version(self):
        p = Packet(ptype=PacketType.DATA, sender_id=SENDER_ID, payload=b"x", signature=SIG)
        raw = bytearray(p.to_bytes())
        raw[4] = 0xFF
        with pytest.raises(InvalidVersionError):
            Packet.from_bytes(bytes(raw))

    def test_truncated_data(self):
        p = Packet(ptype=PacketType.DATA, sender_id=SENDER_ID, payload=b"x", signature=SIG)
        raw = p.to_bytes()
        with pytest.raises(ValueError):
            Packet.from_bytes(raw[:50])

    def test_truncated_payload(self):
        p = Packet(ptype=PacketType.DATA, sender_id=SENDER_ID, payload=b"hello", signature=SIG)
        raw = bytearray(p.to_bytes())
        # Inflate the payload-length field to exceed actual data.
        struct.pack_into("!I", raw, _HEADER_SIZE - 4, 9999)
        with pytest.raises(ValueError):
            Packet.from_bytes(bytes(raw))
