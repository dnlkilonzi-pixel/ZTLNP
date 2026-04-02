"""
ZTLNP trust bootstrap layer.

Most protocols fail at first contact: they either demand pre-shared trust
(impractical) or accept any key on first use without verification (TOFU — fine
until it isn't).  ZTLNP provides a layered model:

Trust levels
------------
UNKNOWN
    The device has never been seen.  All packets from unknown devices are
    *rejected* unless ``allow_tofu=True`` is set on the :class:`TrustStore`.

TOFU  (Trust On First Use)
    The device's key was accepted the first time we saw it.  Packets are
    authenticated against the stored key, but there is no proof that the key
    belongs to the right device.

VERIFIED
    A human operator confirmed the device's key fingerprint out-of-band
    (e.g. by scanning a QR code or reading the fingerprint over a phone call).
    This is the recommended minimum trust level for production use.

ENDORSED
    At least one already-VERIFIED device has signed an endorsement statement
    binding the target's device_id to its Ed25519 public key.  This is the
    web-of-trust level: you can trust a new device if someone you already
    trust vouches for it.

Fingerprint format
------------------
A device fingerprint is the SHA-256 of the raw Ed25519 public key bytes,
formatted as sixteen groups of four uppercase hex characters separated by
colons::

    A1B2:C3D4:E5F6:0A1B:2C3D:4E5F:6A7B:8C9D:1E2F:3A4B:5C6D:7E8F:90AB:CDEF:0123:4567

This is intentionally similar to SSH host-key fingerprints so that operators
already familiar with SSH feel at home.

QR payload format
-----------------
A compact, URL-safe string that can be encoded into a QR code::

    ZTLNP:1:<device_id_hex>:<ed25519_pub_hex>:<fingerprint_hex>

The receiver calls :func:`parse_qr_payload` to extract and validate the fields
and then adds the key to their :class:`TrustStore` at the VERIFIED level.

Web-of-trust endorsements
--------------------------
An endorsement is a 96-byte blob::

    [endorser_device_id (32 B)][target_device_id (32 B)][target_ed25519_pub (32 B)]

signed with the *endorser*'s Ed25519 private key (64-byte signature appended),
for a total of 160 bytes.  The :class:`TrustStore` verifies the signature
against the endorser's own key before accepting the endorsement.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional

from ztlnp.crypto import CryptoEngine
from ztlnp.exceptions import TrustError


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ENDORSEMENT_BODY_SIZE = 96   # 3 × 32 bytes
_ENDORSEMENT_TOTAL_SIZE = 160  # body + 64-byte Ed25519 signature


# ---------------------------------------------------------------------------
# Trust level
# ---------------------------------------------------------------------------

class TrustLevel(IntEnum):
    UNKNOWN = 0
    TOFU = 1
    VERIFIED = 2
    ENDORSED = 3


# ---------------------------------------------------------------------------
# Trust record
# ---------------------------------------------------------------------------

@dataclass
class TrustRecord:
    """
    A single entry in the :class:`TrustStore`.

    Parameters
    ----------
    device_id:
        32-byte SHA-256 of the device's Ed25519 public key.
    ed25519_public:
        Raw 32-byte Ed25519 public key.
    trust_level:
        How this key was verified.
    endorsers:
        Device IDs of peers that issued web-of-trust endorsements for this
        record.
    endorsement_depth:
        Web-of-trust chain depth (0 = directly VERIFIED, 1 = endorsed by a
        VERIFIED peer, 2 = endorsed by a depth-1 peer, …).
    added_at:
        Unix timestamp (float) when the record was created.
    """

    device_id: bytes
    ed25519_public: bytes
    trust_level: TrustLevel = TrustLevel.TOFU
    endorsers: List[bytes] = field(default_factory=list)
    endorsement_depth: int = 0
    added_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if len(self.device_id) != 32:
            raise ValueError("device_id must be 32 bytes")
        if len(self.ed25519_public) != 32:
            raise ValueError("ed25519_public must be 32 bytes")
        # Sanity-check: device_id must be SHA-256(ed25519_public).
        expected_id = hashlib.sha256(self.ed25519_public).digest()
        if self.device_id != expected_id:
            raise TrustError(
                "device_id does not match SHA-256(ed25519_public)"
            )


# ---------------------------------------------------------------------------
# Trust store
# ---------------------------------------------------------------------------

class TrustStore:
    """
    In-memory store of trusted device public keys.

    Parameters
    ----------
    allow_tofu:
        If ``True`` (default), the first HELLO packet from an unknown device
        is automatically accepted at ``TrustLevel.TOFU``.  Set to ``False``
        for strict mode (only pre-loaded or QR-verified keys are accepted).
    min_trust:
        Minimum :class:`TrustLevel` required for a device to be considered
        trusted.  Defaults to :attr:`TrustLevel.TOFU`.
    max_endorsement_depth:
        Maximum web-of-trust chain depth allowed.  Depth 0 = directly
        VERIFIED, depth 1 = endorsed by a VERIFIED peer, depth 2 = endorsed
        by a depth-1 peer, and so on.  Deeper chains are rejected with
        :class:`~ztlnp.exceptions.TrustPoisoningError` to limit trust-chain
        amplification attacks.  Default: 3.
    """

    def __init__(
        self,
        allow_tofu: bool = True,
        min_trust: TrustLevel = TrustLevel.TOFU,
        max_endorsement_depth: int = 3,
    ) -> None:
        self._allow_tofu = allow_tofu
        self._min_trust = min_trust
        self._max_endorsement_depth = max_endorsement_depth
        self._records: Dict[bytes, TrustRecord] = {}
        # Blacklisted device IDs: explicitly distrusted regardless of any record.
        self._blacklist: set = set()

    # ------------------------------------------------------------------
    # Adding / updating records
    # ------------------------------------------------------------------

    def add(
        self,
        ed25519_public: bytes,
        trust_level: TrustLevel = TrustLevel.TOFU,
    ) -> TrustRecord:
        """
        Add or upgrade a device's public key.

        The device_id is automatically derived from the public key.  If a
        record already exists for the device_id and the new *trust_level* is
        higher, it is upgraded; otherwise the existing record is returned
        unchanged.

        Returns
        -------
        TrustRecord
            The current (possibly updated) trust record.
        """
        device_id = hashlib.sha256(ed25519_public).digest()
        if device_id in self._records:
            existing = self._records[device_id]
            if trust_level > existing.trust_level:
                existing.trust_level = trust_level
            return existing

        record = TrustRecord(
            device_id=device_id,
            ed25519_public=ed25519_public,
            trust_level=trust_level,
        )
        self._records[device_id] = record
        return record

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, device_id: bytes) -> Optional[TrustRecord]:
        """Return the :class:`TrustRecord` for *device_id*, or ``None``."""
        return self._records.get(device_id)

    def is_trusted(self, device_id: bytes) -> bool:
        """
        Return ``True`` if *device_id* is known, meets the store's minimum
        trust level, and is **not** blacklisted.
        """
        if device_id in self._blacklist:
            return False
        record = self._records.get(device_id)
        if record is None:
            return False
        return record.trust_level >= self._min_trust

    def distrust(self, device_id: bytes) -> None:
        """
        Actively blacklist *device_id*.

        After this call :meth:`is_trusted` will return ``False`` for the given
        device even if a trust record exists.  Use this to respond to detected
        Sybil nodes or route-poisoning attacks.

        Parameters
        ----------
        device_id:
            32-byte identity to blacklist.
        """
        self._blacklist.add(device_id)

    def is_blacklisted(self, device_id: bytes) -> bool:
        """Return ``True`` if *device_id* has been explicitly distrusted."""
        return device_id in self._blacklist

    def remove_blacklist(self, device_id: bytes) -> None:
        """Remove *device_id* from the blacklist (e.g. after investigation)."""
        self._blacklist.discard(device_id)

    def get_public_key(self, device_id: bytes) -> bytes:
        """
        Return the stored Ed25519 public key for *device_id*.

        Raises
        ------
        TrustError
            If *device_id* is unknown.
        """
        record = self._records.get(device_id)
        if record is None:
            raise TrustError(f"Unknown device: {device_id.hex()}")
        return record.ed25519_public

    # ------------------------------------------------------------------
    # HELLO integration (TOFU)
    # ------------------------------------------------------------------

    def process_hello(self, sender_device_id: bytes, sender_ed25519_pub: bytes) -> TrustRecord:
        """
        Process an incoming HELLO's identity material.

        If the device is already known, the stored key is verified against the
        incoming key.  If it is unknown and ``allow_tofu=True``, the key is
        accepted at ``TrustLevel.TOFU``.

        Returns
        -------
        TrustRecord
            The trust record for the sender.

        Raises
        ------
        TrustError
            If the device is unknown and TOFU is disabled, or if the public key
            does not match the stored record.
        """
        record = self._records.get(sender_device_id)
        if record is not None:
            if record.ed25519_public != sender_ed25519_pub:
                raise TrustError(
                    f"Public key mismatch for device {sender_device_id.hex()}: "
                    "stored key does not match received key (possible MITM)"
                )
            return record

        # Unknown device.
        if not self._allow_tofu:
            raise TrustError(
                f"Unknown device {sender_device_id.hex()} and TOFU is disabled"
            )
        return self.add(sender_ed25519_pub, TrustLevel.TOFU)

    # ------------------------------------------------------------------
    # Fingerprint verification
    # ------------------------------------------------------------------

    def verify_fingerprint(self, device_id: bytes, fingerprint: str) -> bool:
        """
        Confirm a device's key fingerprint out-of-band.

        If the fingerprint matches the stored key, the record is upgraded to
        ``TrustLevel.VERIFIED`` and ``True`` is returned.

        Parameters
        ----------
        device_id:
            32-byte device identifier.
        fingerprint:
            Colon-separated hex fingerprint (as produced by
            :func:`fingerprint_of`).

        Returns
        -------
        bool
            ``True`` if the fingerprint matched and the record was upgraded.
        """
        record = self._records.get(device_id)
        if record is None:
            return False
        if fingerprint_of(record.ed25519_public) == fingerprint:
            record.trust_level = max(record.trust_level, TrustLevel.VERIFIED)
            return True
        return False

    # ------------------------------------------------------------------
    # Web-of-trust endorsements
    # ------------------------------------------------------------------

    def add_endorsement(
        self,
        endorsement_bytes: bytes,
        endorser_device_id: bytes,
    ) -> TrustRecord:
        """
        Verify and accept a signed endorsement blob.

        Parameters
        ----------
        endorsement_bytes:
            160-byte blob: ``[endorser_id(32)][target_id(32)][target_pub(32)]``
            + 64-byte Ed25519 signature.
        endorser_device_id:
            32-byte ID of the endorsing device (used to look up their key).

        Returns
        -------
        TrustRecord
            The (possibly upgraded) trust record of the endorsed device.

        Raises
        ------
        TrustError
            If the endorser is unknown/not trusted, the blob is the wrong size,
            or the signature does not verify.
        """
        if len(endorsement_bytes) != _ENDORSEMENT_TOTAL_SIZE:
            raise TrustError(
                f"Endorsement must be {_ENDORSEMENT_TOTAL_SIZE} bytes, "
                f"got {len(endorsement_bytes)}"
            )

        endorser_record = self._records.get(endorser_device_id)
        if endorser_record is None:
            raise TrustError(
                f"Endorser {endorser_device_id.hex()} is unknown"
            )
        if endorser_record.trust_level < TrustLevel.VERIFIED:
            raise TrustError(
                f"Endorser {endorser_device_id.hex()} is not VERIFIED "
                f"(level: {endorser_record.trust_level.name})"
            )

        # Endorsement depth check — prevent unbounded chain amplification.
        new_depth = endorser_record.endorsement_depth + 1
        if new_depth > self._max_endorsement_depth:
            from ztlnp.exceptions import TrustPoisoningError
            raise TrustPoisoningError(
                f"Endorsement chain depth {new_depth} exceeds "
                f"max_endorsement_depth={self._max_endorsement_depth}. "
                "Possible trust-chain amplification attack."
            )

        body = endorsement_bytes[:_ENDORSEMENT_BODY_SIZE]
        sig = endorsement_bytes[_ENDORSEMENT_BODY_SIZE:]

        if not CryptoEngine.verify(endorser_record.ed25519_public, body, sig):
            raise TrustError("Endorsement signature verification failed")

        # Parse body fields.
        blob_endorser_id = body[:32]
        target_device_id = body[32:64]
        target_ed25519_pub = body[64:96]

        if blob_endorser_id != endorser_device_id:
            raise TrustError(
                "Endorser ID in blob does not match provided endorser_device_id"
            )

        # Add / upgrade the target record and record the endorser.
        record = self.add(target_ed25519_pub, TrustLevel.ENDORSED)
        if endorser_device_id not in record.endorsers:
            record.endorsers.append(endorser_device_id)
        # Set endorsement depth on the target.
        record.endorsement_depth = new_depth
        return record

    def all_records(self) -> List[TrustRecord]:
        """Return all stored trust records."""
        return list(self._records.values())


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def fingerprint_of(ed25519_public: bytes) -> str:
    """
    Compute the human-readable SHA-256 fingerprint of an Ed25519 public key.

    The fingerprint is the SHA-256 hash of the raw public key bytes, formatted
    as sixteen groups of four uppercase hex characters separated by colons::

        A1B2:C3D4:E5F6:0A1B:2C3D:4E5F:6A7B:8C9D:1E2F:3A4B:5C6D:7E8F:90AB:CDEF:0123:4567

    This is 79 characters long and suitable for display in a terminal or QR
    code verification UI.
    """
    digest = hashlib.sha256(ed25519_public).hexdigest().upper()
    return ":".join(digest[i : i + 4] for i in range(0, 64, 4))


def encode_qr_payload(device_id: bytes, ed25519_public: bytes) -> str:
    """
    Encode identity material as a compact, URL-safe string for QR code use.

    The returned string has the form::

        ZTLNP:1:<device_id_hex>:<ed25519_pub_hex>:<fingerprint_hex>

    Any QR code library can encode this string; the receiver calls
    :func:`parse_qr_payload` to recover the fields.

    Parameters
    ----------
    device_id:
        32-byte SHA-256 of the Ed25519 public key.
    ed25519_public:
        Raw 32-byte Ed25519 public key.
    """
    fp = hashlib.sha256(ed25519_public).hexdigest()
    return f"ZTLNP:1:{device_id.hex()}:{ed25519_public.hex()}:{fp}"


def parse_qr_payload(payload: str) -> tuple[bytes, bytes]:
    """
    Parse a QR payload produced by :func:`encode_qr_payload`.

    Returns
    -------
    (device_id, ed25519_public)

    Raises
    ------
    TrustError
        If the payload is malformed, the version is unsupported, or the
        fingerprint does not match.
    """
    parts = payload.split(":")
    if len(parts) != 5 or parts[0] != "ZTLNP" or parts[1] != "1":
        raise TrustError(f"Invalid QR payload format: {payload!r}")

    try:
        device_id = bytes.fromhex(parts[2])
        ed25519_public = bytes.fromhex(parts[3])
        fp_from_payload = parts[4]
    except ValueError as exc:
        raise TrustError(f"QR payload hex decode error: {exc}") from exc

    if len(device_id) != 32 or len(ed25519_public) != 32:
        raise TrustError("QR payload fields have wrong length")

    expected_fp = hashlib.sha256(ed25519_public).hexdigest()
    if fp_from_payload != expected_fp:
        raise TrustError("QR payload fingerprint does not match the public key")

    expected_device_id = hashlib.sha256(ed25519_public).digest()
    if device_id != expected_device_id:
        raise TrustError("QR payload device_id does not match SHA-256(ed25519_public)")

    return device_id, ed25519_public


def create_endorsement(
    endorser_private_key,  # Ed25519PrivateKey
    endorser_device_id: bytes,
    target_device_id: bytes,
    target_ed25519_public: bytes,
) -> bytes:
    """
    Create a 160-byte signed endorsement blob.

    The endorser signs the concatenation of the three 32-byte IDs/keys to
    produce a web-of-trust voucher that any :class:`TrustStore` can verify.

    Parameters
    ----------
    endorser_private_key:
        Ed25519 private key of the endorsing device.
    endorser_device_id:
        32-byte device identifier of the endorser.
    target_device_id:
        32-byte device identifier of the device being endorsed.
    target_ed25519_public:
        Raw 32-byte Ed25519 public key of the target device.

    Returns
    -------
    bytes
        160-byte endorsement blob.
    """
    body = endorser_device_id + target_device_id + target_ed25519_public
    signature = CryptoEngine.sign(endorser_private_key, body)
    return body + signature
