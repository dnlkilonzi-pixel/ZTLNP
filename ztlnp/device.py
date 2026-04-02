"""
ZTLNP device: represents a network endpoint with a stable identity.

A ``Device`` owns:
- a long-lived Ed25519 identity key pair,
- a SHA-256 device ID derived from the public key,
- the ability to initiate or respond to handshakes,
- a registry of established :class:`~ztlnp.session.Session` objects.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ztlnp.crypto import CryptoEngine
from ztlnp.exceptions import SessionNotFoundError
from ztlnp.session import Session


class Device:
    """
    A ZTLNP network device.

    Parameters
    ----------
    name:
        Human-readable label used only for debugging / logging.
    """

    def __init__(self, name: str = "device") -> None:
        self.name = name

        # Long-lived Ed25519 identity key pair.
        self._identity_private: Ed25519PrivateKey
        self._identity_private, self._identity_public_bytes = (
            CryptoEngine.generate_identity_keypair()
        )

        # Device ID: SHA-256 of the Ed25519 public key (32 bytes).
        self.device_id: bytes = hashlib.sha256(self._identity_public_bytes).digest()

        # Map from peer_device_id → Session.
        self._sessions: Dict[bytes, Session] = {}

        # Ephemeral X25519 keys: one per in-progress handshake.
        # Keyed by peer_device_id so concurrent handshakes are possible.
        self._ephemeral_private: Dict[bytes, X25519PrivateKey] = {}
        self._ephemeral_public: Dict[bytes, bytes] = {}

        # Ed25519 public keys for peers that have sent a HELLO but have not
        # yet completed the key exchange (no Session exists yet).
        # Maps peer_device_id → raw Ed25519 public key bytes.
        self._pending_peer_keys: Dict[bytes, bytes] = {}

    # ------------------------------------------------------------------
    # Public-key accessors
    # ------------------------------------------------------------------

    @property
    def identity_public_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key."""
        return self._identity_public_bytes

    # ------------------------------------------------------------------
    # Key-exchange state management
    # ------------------------------------------------------------------

    def register_pending_peer(self, peer_id: bytes, peer_ed25519_public: bytes) -> None:
        """
        Register a peer's Ed25519 public key before a session is established.

        Called after a HELLO is received so that KEY_EXCHANGE packets can be
        verified before ``complete_key_exchange`` has been invoked.
        """
        self._pending_peer_keys[peer_id] = peer_ed25519_public

    def generate_ephemeral_keypair(self, peer_id: bytes) -> bytes:
        """
        Generate (or reuse) an ephemeral X25519 key pair for a peer handshake.

        Returns the raw 32-byte X25519 public key to be sent to the peer.
        """
        if peer_id not in self._ephemeral_private:
            priv, pub = CryptoEngine.generate_x25519_keypair()
            self._ephemeral_private[peer_id] = priv
            self._ephemeral_public[peer_id] = pub
        return self._ephemeral_public[peer_id]

    def complete_key_exchange(
        self,
        peer_id: bytes,
        peer_ed25519_public: bytes,
        peer_x25519_public: bytes,
        i_am_initiator: bool,
    ) -> Session:
        """
        Complete an X25519 key exchange and store the resulting session.

        Parameters
        ----------
        peer_id:
            32-byte device identifier of the remote peer.
        peer_ed25519_public:
            Raw 32-byte Ed25519 public key of the peer (used to verify packets).
        peer_x25519_public:
            Raw 32-byte X25519 ephemeral public key received from the peer.
        i_am_initiator:
            True if this device initiated the connection (determines the order
            of device IDs in the HKDF info string, so both sides derive the
            same key).
        """
        if peer_id not in self._ephemeral_private:
            raise ValueError(
                "No ephemeral key pair for peer; call generate_ephemeral_keypair() first"
            )

        shared_secret = CryptoEngine.x25519_exchange(
            self._ephemeral_private[peer_id], peer_x25519_public
        )

        if i_am_initiator:
            initiator_id, responder_id = self.device_id, peer_id
        else:
            initiator_id, responder_id = peer_id, self.device_id

        session_key = CryptoEngine.derive_session_key(
            shared_secret, initiator_id, responder_id
        )
        mac_key = CryptoEngine.derive_mac_key(
            shared_secret, initiator_id, responder_id
        )

        session = Session(
            peer_id=peer_id,
            peer_ed25519_public=peer_ed25519_public,
            session_key=session_key,
            mac_key=mac_key,
        )
        self._sessions[peer_id] = session

        # Clean up ephemeral key material and pending key once the exchange is done.
        del self._ephemeral_private[peer_id]
        del self._ephemeral_public[peer_id]
        self._pending_peer_keys.pop(peer_id, None)

        return session

    # ------------------------------------------------------------------
    # Session lookup
    # ------------------------------------------------------------------

    def get_session(self, peer_id: bytes) -> Session:
        """
        Retrieve an established session.

        Raises
        ------
        SessionNotFoundError
            If no session exists for *peer_id*.
        """
        try:
            return self._sessions[peer_id]
        except KeyError:
            raise SessionNotFoundError(
                f"No established session for peer {peer_id.hex()}"
            ) from None

    def has_session(self, peer_id: bytes) -> bool:
        """Return ``True`` if a session with *peer_id* is established."""
        return peer_id in self._sessions

    def remove_session(self, peer_id: bytes) -> None:
        """Remove the session associated with *peer_id* (e.g. after BYE)."""
        self._sessions.pop(peer_id, None)

    # ------------------------------------------------------------------
    # Packet construction
    # ------------------------------------------------------------------

    def build_hello_packet(self, recipient_id: bytes = None) -> "Packet":  # noqa: F821
        """
        Build a HELLO packet advertising this device's identity and ephemeral
        X25519 public key.

        The payload layout is::

            [32 bytes Ed25519 public key][32 bytes X25519 public key]

        The packet is *not* encrypted (no session key exists yet) but it *is*
        signed with the sender's Ed25519 key so the recipient can verify the
        sender's identity.
        """
        from ztlnp.packet import Packet, PacketType, PacketFlags, BROADCAST_ID

        if recipient_id is None:
            recipient_id = BROADCAST_ID

        x25519_pub = self.generate_ephemeral_keypair(recipient_id)
        payload = self._identity_public_bytes + x25519_pub

        packet = Packet(
            ptype=PacketType.HELLO,
            sender_id=self.device_id,
            payload=payload,
            recipient_id=recipient_id,
            flags=PacketFlags.NONE,
            sequence=0,
        )
        packet.signature = CryptoEngine.sign_packet(self._identity_private, packet)
        return packet

    def build_data_packet(
        self, peer_id: bytes, plaintext: bytes
    ) -> "Packet":  # noqa: F821
        """
        Build an encrypted, signed DATA packet for *peer_id*.

        Uses Ed25519 signing (full identity proof) for all control packets.
        For DATA packets in an established session, prefer
        :meth:`build_data_packet_mac` for better throughput.

        Raises
        ------
        SessionNotFoundError
            If no session exists for *peer_id*.
        """
        from ztlnp.packet import Packet, PacketType, PacketFlags

        session = self.get_session(peer_id)
        nonce = CryptoEngine.generate_nonce()
        ciphertext = CryptoEngine.encrypt(session.session_key, nonce, plaintext)

        packet = Packet(
            ptype=PacketType.DATA,
            sender_id=self.device_id,
            payload=ciphertext,
            recipient_id=peer_id,
            flags=PacketFlags.ENCRYPTED,
            sequence=session.next_sequence(),
            nonce=nonce,
        )
        packet.signature = CryptoEngine.sign_packet(self._identity_private, packet)
        return packet

    def build_data_packet_mac(
        self, peer_id: bytes, plaintext: bytes
    ) -> "Packet":  # noqa: F821
        """
        Build an encrypted DATA packet authenticated with HMAC-SHA-512 instead
        of an Ed25519 signature.

        This ``MAC_AUTH`` fast-path is ~10–40× faster than full Ed25519 signing
        for high-throughput data transfer, while still providing per-packet
        authentication.  The trade-off is that HMAC authentication requires an
        already-established shared session key — it does not prove identity to
        a third party the way Ed25519 does.

        Raises
        ------
        SessionNotFoundError
            If no session exists for *peer_id*.
        """
        from ztlnp.packet import Packet, PacketType, PacketFlags

        session = self.get_session(peer_id)
        nonce = CryptoEngine.generate_nonce()
        ciphertext = CryptoEngine.encrypt(session.session_key, nonce, plaintext)

        packet = Packet(
            ptype=PacketType.DATA,
            sender_id=self.device_id,
            payload=ciphertext,
            recipient_id=peer_id,
            flags=PacketFlags.ENCRYPTED | PacketFlags.MAC_AUTH,
            sequence=session.next_sequence(),
            nonce=nonce,
        )
        packet.signature = CryptoEngine.mac_packet(session.mac_key, packet)
        return packet

    def build_ack_packet(self, peer_id: bytes, acked_sequence: int) -> "Packet":  # noqa: F821
        """
        Build an ACK packet confirming receipt of a DATA packet.
        """
        from ztlnp.packet import Packet, PacketType, PacketFlags
        import struct

        session = self.get_session(peer_id)
        nonce = CryptoEngine.generate_nonce()
        ack_payload = struct.pack("!I", acked_sequence)
        ciphertext = CryptoEngine.encrypt(session.session_key, nonce, ack_payload)

        packet = Packet(
            ptype=PacketType.ACK,
            sender_id=self.device_id,
            payload=ciphertext,
            recipient_id=peer_id,
            flags=PacketFlags.ENCRYPTED,
            sequence=session.next_sequence(),
            nonce=nonce,
        )
        packet.signature = CryptoEngine.sign_packet(self._identity_private, packet)
        return packet

    def build_bye_packet(self, peer_id: bytes) -> "Packet":  # noqa: F821
        """
        Build a signed BYE packet to gracefully close the session with *peer_id*.
        """
        from ztlnp.packet import Packet, PacketType, PacketFlags

        session = self.get_session(peer_id)
        nonce = CryptoEngine.generate_nonce()
        ciphertext = CryptoEngine.encrypt(session.session_key, nonce, b"BYE")

        packet = Packet(
            ptype=PacketType.BYE,
            sender_id=self.device_id,
            payload=ciphertext,
            recipient_id=peer_id,
            flags=PacketFlags.ENCRYPTED,
            sequence=session.next_sequence(),
            nonce=nonce,
        )
        packet.signature = CryptoEngine.sign_packet(self._identity_private, packet)
        return packet

    # ------------------------------------------------------------------
    # Packet reception and verification
    # ------------------------------------------------------------------

    def receive_packet(self, raw: bytes) -> "Packet":  # noqa: F821
        """
        Parse, authenticate, and replay-check an incoming packet.

        For HELLO packets the signature is verified using the Ed25519 public
        key embedded in the payload (no session required).

        For packets with the ``MAC_AUTH`` flag the ``signature`` field is
        verified as an HMAC-SHA-512 tag using the session's MAC key (faster
        than Ed25519; only valid for established sessions).

        For all other packet types the Ed25519 signature is verified using the
        public key stored in the established session or pending-peer registry.

        Returns
        -------
        Packet
            The parsed and verified packet.

        Raises
        ------
        InvalidMagicError / InvalidVersionError
            Bad wire format.
        SignatureVerificationError
            Signature or MAC tag did not verify.
        ReplayAttackError
            Timestamp or sequence number indicates a replay.
        SessionNotFoundError
            Non-HELLO packet received without an established session.
        """
        from ztlnp.packet import Packet, PacketType, PacketFlags
        from ztlnp.exceptions import SignatureVerificationError

        packet = Packet.from_bytes(raw)

        if packet.ptype == PacketType.HELLO:
            # Public key is embedded in the payload (first 32 bytes).
            sender_ed25519_pub = packet.payload[:32]
            if not CryptoEngine.verify_packet(sender_ed25519_pub, packet):
                raise SignatureVerificationError(
                    "HELLO packet signature verification failed"
                )
            return packet

        # All other packet types require either an established session or a
        # pending peer key (set during the handshake after a HELLO is received
        # but before KEY_EXCHANGE completes).
        if packet.sender_id in self._sessions:
            session = self._sessions[packet.sender_id]
            is_session_packet = True
        elif packet.sender_id in self._pending_peer_keys:
            session = None
            is_session_packet = False
        else:
            raise SessionNotFoundError(
                f"No established session for peer {packet.sender_id.hex()}"
            )

        # Choose verification path: HMAC (MAC_AUTH) or Ed25519.
        if is_session_packet and (packet.flags & PacketFlags.MAC_AUTH):
            if not CryptoEngine.verify_packet_mac(session.mac_key, packet):
                raise SignatureVerificationError(
                    f"MAC_AUTH tag verification failed for peer {packet.sender_id.hex()}"
                )
        else:
            sender_ed25519_pub = (
                session.peer_ed25519_public
                if is_session_packet
                else self._pending_peer_keys[packet.sender_id]
            )
            if not CryptoEngine.verify_packet(sender_ed25519_pub, packet):
                raise SignatureVerificationError(
                    f"Packet signature verification failed for peer {packet.sender_id.hex()}"
                )

        if is_session_packet:
            session.check_replay(packet.sequence, packet.timestamp_ms)

        return packet

    def decrypt_packet(self, packet: "Packet") -> bytes:  # noqa: F821
        """
        Decrypt the payload of an incoming DATA, ACK, or BYE packet.

        Raises
        ------
        SessionNotFoundError
            If no session exists for the packet's sender.
        cryptography.exceptions.InvalidTag
            If AES-GCM authentication fails (packet was tampered with).
        """
        session = self.get_session(packet.sender_id)
        return CryptoEngine.decrypt(session.session_key, packet.nonce, packet.payload)

    def __repr__(self) -> str:
        return f"Device(name={self.name!r}, id={self.device_id.hex()[:16]}...)"
