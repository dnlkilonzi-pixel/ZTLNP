"""
ZTLNP custom exceptions.
"""


class ZTLNPError(Exception):
    """Base exception for all ZTLNP errors."""


class InvalidMagicError(ZTLNPError):
    """Packet does not begin with the expected magic bytes."""


class InvalidVersionError(ZTLNPError):
    """Packet carries an unsupported protocol version."""


class SignatureVerificationError(ZTLNPError):
    """Ed25519 signature on the packet did not verify."""


class ReplayAttackError(ZTLNPError):
    """Packet appears to be a replay (stale timestamp or duplicate sequence)."""


class SessionNotFoundError(ZTLNPError):
    """No established session exists for the given peer."""


class HandshakeError(ZTLNPError):
    """Key-exchange handshake could not be completed."""


class TrustError(ZTLNPError):
    """A trust-store operation failed (unknown peer, bad endorsement, etc.)."""


class RoutingError(ZTLNPError):
    """No route exists to the destination device."""


class RetransmitError(ZTLNPError):
    """Reliable delivery failed after exhausting all retransmission attempts."""


class KeyRotationError(ZTLNPError):
    """A key-rotation transition was invalid or could not be applied."""


class TrustPoisoningError(ZTLNPError):
    """A trust or routing operation was rejected due to poisoning-defence rules."""
