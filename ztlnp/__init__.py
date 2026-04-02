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
- Trust is bootstrapped via TOFU, fingerprint verification, or web-of-trust
  endorsements.
- The protocol is transport-agnostic (UDP, in-process, BLE, LoRa, etc.).
- Mesh routing: packets are forwarded by identity, not by IP.
- Reliable delivery: stop-and-wait ARQ or sliding-window ARQ with SACK.
- Performance: DATA packets in established sessions may use HMAC-SHA-512 instead
  of Ed25519 (~10–40× faster) via the MAC_AUTH flag.
- Forward-secure identity rotation: signed key transitions preserve trust chains.
- Route-poisoning defence: trust caps, endorsement depth limits, blacklisting.
- Traffic analysis resistance: payload padding, timing jitter, cover traffic.

Public API
----------
Device       -- represents a network node with an identity key pair.
Packet       -- the wire-format unit; carries type, sender/recipient IDs,
                timestamp, sequence number, nonce, encrypted payload, and a
                64-byte Ed25519 signature (or HMAC-SHA-512 tag).
PacketType   -- enumeration of all defined packet types.
Session      -- shared-secret state between two devices after the key exchange.
ZTLNPError   -- base exception for all protocol errors.

Trust bootstrap
---------------
TrustStore   -- in-memory trust store with TOFU, fingerprint, and web-of-trust.
TrustRecord  -- a single entry in the trust store.
TrustLevel   -- UNKNOWN / TOFU / VERIFIED / ENDORSED.
fingerprint_of  -- human-readable SHA-256 fingerprint of an Ed25519 key.
encode_qr_payload / parse_qr_payload  -- QR-code-friendly key encoding.
create_endorsement  -- produce a signed web-of-trust endorsement blob.

Transport abstraction
---------------------
Transport          -- abstract base class.
InProcessTransport -- in-memory transport for tests.
UdpTransport       -- UDP socket transport.
TransportTimeout / TransportClosed  -- transport exceptions.

Routing / mesh
--------------
Router       -- identity-based packet forwarding with trust-poisoning defence.
RouteTable   -- route collection with best-route selection.
RouteEntry   -- single route record (transport, hop_count, trust_score, latency).

Reliability
-----------
ReliableChannel      -- stop-and-wait ARQ with exponential-backoff retransmission.
PendingPacket        -- an in-flight (unacknowledged) DATA packet (stop-and-wait).
SlidingWindowChannel -- sliding-window ARQ with SACK; much higher throughput.
SackFrame            -- selective-ACK state frame.
WindowedPacket       -- an in-flight packet in the sliding-window send buffer.

Identity rotation
-----------------
KeyTransition   -- signed blob committing a device to a new Ed25519 key.
RotationManager -- validates and applies key transitions to a TrustStore.
RotationRecord  -- a single rotation history entry.
create_key_transition -- helper to sign a new KeyTransition.
Device.rotate_key     -- rotate this device's identity key.

Privacy
-------
PaddingStrategy -- enum: NONE / FIXED / RANDOM / BLOCK.
pad_to_size     -- append padding to a plaintext before encryption.
strip_padding   -- remove padding after decryption.
random_jitter_ms / jitter_sleep -- inject send-timing randomness.
CoverTraffic    -- generate dummy DATA packets at a fixed rate.
"""

from ztlnp.packet import Packet, PacketType, PacketFlags, MAGIC, VERSION, SEQUENCE_OFFSET
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
    TrustError,
    RoutingError,
    RetransmitError,
    KeyRotationError,
    TrustPoisoningError,
)
from ztlnp.trust import (
    TrustLevel,
    TrustRecord,
    TrustStore,
    fingerprint_of,
    encode_qr_payload,
    parse_qr_payload,
    create_endorsement,
)
from ztlnp.transport import (
    Transport,
    InProcessTransport,
    UdpTransport,
    TransportTimeout,
    TransportClosed,
)
from ztlnp.router import Router, RouteTable, RouteEntry
from ztlnp.reliability import ReliableChannel, PendingPacket
from ztlnp.sliding_window import SlidingWindowChannel, SackFrame, WindowedPacket
from ztlnp.identity import (
    KeyTransition,
    RotationManager,
    RotationRecord,
    create_key_transition,
)
from ztlnp.privacy import (
    PaddingStrategy,
    pad_to_size,
    strip_padding,
    random_jitter_ms,
    jitter_sleep,
    CoverTraffic,
)

__all__ = [
    # Core protocol
    "Packet", "PacketType", "PacketFlags", "MAGIC", "VERSION", "SEQUENCE_OFFSET",
    "CryptoEngine",
    "Device",
    "Session",
    "Protocol", "ProtocolState",
    # Exceptions
    "ZTLNPError", "InvalidMagicError", "InvalidVersionError",
    "SignatureVerificationError", "ReplayAttackError",
    "SessionNotFoundError", "HandshakeError",
    "TrustError", "RoutingError", "RetransmitError",
    "KeyRotationError", "TrustPoisoningError",
    # Trust bootstrap
    "TrustLevel", "TrustRecord", "TrustStore",
    "fingerprint_of", "encode_qr_payload", "parse_qr_payload",
    "create_endorsement",
    # Transport
    "Transport", "InProcessTransport", "UdpTransport",
    "TransportTimeout", "TransportClosed",
    # Routing
    "Router", "RouteTable", "RouteEntry",
    # Reliability (stop-and-wait)
    "ReliableChannel", "PendingPacket",
    # Reliability (sliding window)
    "SlidingWindowChannel", "SackFrame", "WindowedPacket",
    # Identity rotation
    "KeyTransition", "RotationManager", "RotationRecord", "create_key_transition",
    # Privacy / traffic analysis resistance
    "PaddingStrategy", "pad_to_size", "strip_padding",
    "random_jitter_ms", "jitter_sleep", "CoverTraffic",
]

