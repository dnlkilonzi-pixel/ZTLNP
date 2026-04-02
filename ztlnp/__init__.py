"""
ZTLNP - Zero Trust Local Network Protocol
==========================================

A custom network protocol that authenticates every packet and trusts nothing by
default — not even hosts on the same LAN segment.

Key properties:
- Every packet is signed with the sender's Ed25519 identity key.
- All payload data is encrypted with AES-256-GCM using a session key derived
  from an X25519 Diffie-Hellman key exchange.
- Replay attacks are prevented by timestamp bounds and monotonic sequence numbers.
- Device identity is derived from public-key material, not from IP addresses or
  MAC addresses.

Public API
----------
Device       -- represents a network node with an identity key pair.
Packet       -- the wire-format unit; carries type, sender/recipient IDs,
                timestamp, sequence number, nonce, encrypted payload, and a
                64-byte Ed25519 signature.
PacketType   -- enumeration of all defined packet types.
Session      -- shared-secret state between two devices after the key exchange.
ZTLNPError   -- base exception for all protocol errors.
"""

from ztlnp.packet import Packet, PacketType, PacketFlags, MAGIC, VERSION
from ztlnp.crypto import CryptoEngine
from ztlnp.device import Device
from ztlnp.session import Session
from ztlnp.protocol import Protocol, ProtocolState
from ztlnp.exceptions import (
    ZTLNPError,
    InvalidMagicError,
    InvalidVersionError,
    SignatureVerificationError,
    ReplayAttackError,
    SessionNotFoundError,
    HandshakeError,
)

__all__ = [
    "Packet",
    "PacketType",
    "PacketFlags",
    "MAGIC",
    "VERSION",
    "CryptoEngine",
    "Device",
    "Session",
    "Protocol",
    "ProtocolState",
    "ZTLNPError",
    "InvalidMagicError",
    "InvalidVersionError",
    "SignatureVerificationError",
    "ReplayAttackError",
    "SessionNotFoundError",
    "HandshakeError",
]
