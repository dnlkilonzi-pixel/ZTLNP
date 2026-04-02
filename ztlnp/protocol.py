"""
ZTLNP protocol state machine.

The ``Protocol`` class drives the full handshake lifecycle:

    IDLE  →  HELLO_SENT  →  KEY_EXCHANGE  →  ESTABLISHED  →  CLOSED

Usage (initiator side)
----------------------
::

    proto = Protocol(local_device)
    hello_bytes = proto.initiate(peer_id)          # → send to peer
    # peer sends back its HELLO …
    ke_bytes = proto.process_incoming(peer_hello)  # → send KEY_EXCHANGE
    # peer sends back KEY_EXCHANGE …
    proto.process_incoming(peer_ke)                # session ESTABLISHED

Usage (responder side)
----------------------
::

    proto = Protocol(local_device)
    # initiator sends HELLO …
    response = proto.process_incoming(initiator_hello)   # → send back
    # initiator sends KEY_EXCHANGE …
    proto.process_incoming(initiator_ke)                 # ESTABLISHED

Once the state is ``ESTABLISHED`` use :meth:`send_data` /
:meth:`receive_data` to exchange application data.
"""

from __future__ import annotations

import struct
from enum import Enum, auto
from typing import Optional

from ztlnp.device import Device
from ztlnp.exceptions import HandshakeError, SessionNotFoundError
from ztlnp.packet import Packet, PacketType, PacketFlags, BROADCAST_ID


class ProtocolState(Enum):
    IDLE = auto()
    HELLO_SENT = auto()
    HELLO_RECEIVED = auto()
    KEY_EXCHANGE_SENT = auto()
    ESTABLISHED = auto()
    CLOSED = auto()
    ERROR = auto()


class Protocol:
    """
    Per-session protocol state machine.

    One ``Protocol`` instance manages the handshake and data exchange with a
    **single** remote peer.

    Parameters
    ----------
    local_device:
        The :class:`~ztlnp.device.Device` that owns this protocol instance.
    """

    def __init__(self, local_device: Device) -> None:
        self.local = local_device
        self.state: ProtocolState = ProtocolState.IDLE
        self._peer_id: Optional[bytes] = None
        self._peer_ed25519_pub: Optional[bytes] = None
        self._peer_x25519_pub: Optional[bytes] = None
        self._i_am_initiator: bool = False

    # ------------------------------------------------------------------
    # Initiator entry point
    # ------------------------------------------------------------------

    def initiate(self, peer_id: bytes) -> bytes:
        """
        Begin a handshake with *peer_id*.

        Returns
        -------
        bytes
            Serialised HELLO packet to transmit to the peer.

        Raises
        ------
        HandshakeError
            If this protocol instance is not in the IDLE state.
        """
        if self.state != ProtocolState.IDLE:
            raise HandshakeError(
                f"Cannot initiate: current state is {self.state.name}"
            )

        self._peer_id = peer_id
        self._i_am_initiator = True

        hello = self.local.build_hello_packet(recipient_id=peer_id)
        self.state = ProtocolState.HELLO_SENT
        return hello.to_bytes()

    # ------------------------------------------------------------------
    # Unified incoming-packet processor
    # ------------------------------------------------------------------

    def process_incoming(self, raw: bytes) -> Optional[bytes]:
        """
        Parse and handle an incoming packet, advancing the state machine.

        Returns
        -------
        Optional[bytes]
            A serialised response packet to transmit, or ``None`` if no
            response is required at this step.

        Raises
        ------
        HandshakeError
            On any protocol-level inconsistency.
        SignatureVerificationError / ReplayAttackError
            Propagated from :meth:`~ztlnp.device.Device.receive_packet`.
        """
        if self.state in (ProtocolState.CLOSED, ProtocolState.ERROR):
            raise HandshakeError(
                f"Protocol is in terminal state {self.state.name}; "
                "create a new Protocol instance to restart"
            )

        packet = self.local.receive_packet(raw)

        if packet.ptype == PacketType.HELLO:
            return self._handle_hello(packet)
        elif packet.ptype == PacketType.KEY_EXCHANGE:
            return self._handle_key_exchange(packet)
        elif packet.ptype == PacketType.DATA:
            return self._handle_data(packet)
        elif packet.ptype == PacketType.ACK:
            return self._handle_ack(packet)
        elif packet.ptype == PacketType.BYE:
            return self._handle_bye(packet)
        elif packet.ptype == PacketType.ERROR:
            self.state = ProtocolState.ERROR
            return None
        else:
            raise HandshakeError(f"Unknown packet type: {packet.ptype}")

    # ------------------------------------------------------------------
    # Application data helpers
    # ------------------------------------------------------------------

    def send_data(self, plaintext: bytes) -> bytes:
        """
        Encrypt and sign *plaintext* for the current peer.

        Returns
        -------
        bytes
            Serialised DATA packet ready to transmit.

        Raises
        ------
        HandshakeError
            If the session is not yet established.
        """
        self._require_established()
        return self.local.build_data_packet(self._peer_id, plaintext).to_bytes()

    def receive_data(self, raw: bytes) -> bytes:
        """
        Verify, replay-check, and decrypt an incoming DATA packet.

        Returns
        -------
        bytes
            Decrypted plaintext.
        """
        self._require_established()
        packet = self.local.receive_packet(raw)
        if packet.ptype != PacketType.DATA:
            raise HandshakeError(
                f"Expected DATA packet, got {packet.ptype.name}"
            )
        return self.local.decrypt_packet(packet)

    # ------------------------------------------------------------------
    # Internal state-machine handlers
    # ------------------------------------------------------------------

    def _handle_hello(self, packet: Packet) -> Optional[bytes]:
        """Process a received HELLO and respond appropriately."""
        # Extract public keys from payload.
        if len(packet.payload) < 64:
            raise HandshakeError("HELLO payload too short (expected 64 bytes)")

        peer_ed25519_pub = packet.payload[:32]
        peer_x25519_pub = packet.payload[32:64]

        self._peer_id = packet.sender_id
        self._peer_ed25519_pub = peer_ed25519_pub
        self._peer_x25519_pub = peer_x25519_pub

        if self.state == ProtocolState.IDLE:
            # We are the responder: send our own HELLO back.
            self._i_am_initiator = False
            self.local.generate_ephemeral_keypair(self._peer_id)
            # Register the peer's Ed25519 key so KEY_EXCHANGE can be verified
            # before the session is formally established.
            self.local.register_pending_peer(self._peer_id, peer_ed25519_pub)
            hello = self.local.build_hello_packet(recipient_id=self._peer_id)
            self.state = ProtocolState.HELLO_RECEIVED
            return hello.to_bytes()

        elif self.state == ProtocolState.HELLO_SENT:
            # We are the initiator: peer responded with their HELLO.
            # Proceed to complete the key exchange and send KEY_EXCHANGE.
            session = self.local.complete_key_exchange(
                peer_id=self._peer_id,
                peer_ed25519_public=peer_ed25519_pub,
                peer_x25519_public=peer_x25519_pub,
                i_am_initiator=True,
            )
            ke_packet = self._build_key_exchange_packet(session.next_sequence())
            self.state = ProtocolState.KEY_EXCHANGE_SENT
            return ke_packet

        else:
            raise HandshakeError(
                f"Received unexpected HELLO in state {self.state.name}"
            )

    def _handle_key_exchange(self, packet: Packet) -> Optional[bytes]:
        """Process a KEY_EXCHANGE packet."""
        if self.state == ProtocolState.HELLO_RECEIVED:
            # We are the responder: initiator sent KEY_EXCHANGE.
            # Complete our side of the key exchange now.
            self.local.complete_key_exchange(
                peer_id=self._peer_id,
                peer_ed25519_public=self._peer_ed25519_pub,
                peer_x25519_public=self._peer_x25519_pub,
                i_am_initiator=False,
            )
            # Verify and record the key-exchange packet for replay prevention.
            # NOTE: receive_packet() verified the signature using the pending
            # peer key; now that the session exists we do the replay check.
            session = self.local.get_session(self._peer_id)
            session.check_replay(packet.sequence, packet.timestamp_ms)

            # Decrypt and verify the KEY_EXCHANGE payload.
            plaintext = self.local.decrypt_packet(packet)
            if plaintext != b"KEY_EXCHANGE_OK":
                raise HandshakeError("KEY_EXCHANGE payload mismatch")

            self.state = ProtocolState.ESTABLISHED
            # Send our own KEY_EXCHANGE confirmation back.
            ke_packet = self._build_key_exchange_packet(session.next_sequence())
            return ke_packet

        elif self.state == ProtocolState.KEY_EXCHANGE_SENT:
            # We are the initiator: responder confirmed.
            # receive_packet() already ran the replay check via the session.
            session = self.local.get_session(self._peer_id)

            plaintext = self.local.decrypt_packet(packet)
            if plaintext != b"KEY_EXCHANGE_OK":
                raise HandshakeError("KEY_EXCHANGE payload mismatch")

            self.state = ProtocolState.ESTABLISHED
            return None

        else:
            raise HandshakeError(
                f"Received unexpected KEY_EXCHANGE in state {self.state.name}"
            )

    def _handle_data(self, packet: Packet) -> Optional[bytes]:
        """Accept a DATA packet (application layer handles the payload)."""
        self._require_established()
        # Verification and replay-check already done in receive_packet.
        return None

    def _handle_ack(self, packet: Packet) -> Optional[bytes]:
        """Accept an ACK packet."""
        self._require_established()
        return None

    def _handle_bye(self, packet: Packet) -> Optional[bytes]:
        """Handle a BYE packet — tear down the session."""
        if self.state == ProtocolState.ESTABLISHED:
            # receive_packet() already ran the replay check via the session.
            self.local.remove_session(self._peer_id)
            self.state = ProtocolState.CLOSED
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_key_exchange_packet(self, seq: int) -> bytes:
        """Build a signed, encrypted KEY_EXCHANGE confirmation packet."""
        from ztlnp.crypto import CryptoEngine

        session = self.local.get_session(self._peer_id)
        nonce = CryptoEngine.generate_nonce()
        ciphertext = CryptoEngine.encrypt(
            session.session_key, nonce, b"KEY_EXCHANGE_OK"
        )
        packet = Packet(
            ptype=PacketType.KEY_EXCHANGE,
            sender_id=self.local.device_id,
            payload=ciphertext,
            recipient_id=self._peer_id,
            flags=PacketFlags.ENCRYPTED,
            sequence=seq,
            nonce=nonce,
        )
        packet.signature = CryptoEngine.sign_packet(
            self.local._identity_private, packet
        )
        return packet.to_bytes()

    def _require_established(self) -> None:
        if self.state != ProtocolState.ESTABLISHED:
            raise HandshakeError(
                f"Session is not established (state: {self.state.name})"
            )

    @property
    def peer_id(self) -> Optional[bytes]:
        """The 32-byte device ID of the remote peer, once known."""
        return self._peer_id
