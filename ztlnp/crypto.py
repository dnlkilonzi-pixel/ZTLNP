"""
ZTLNP cryptographic engine.

Algorithms used
---------------
- **Ed25519** (identity / signing)  – one key pair per device, long-lived.
- **X25519**  (key agreement)       – one ephemeral key pair per session.
- **HKDF-SHA-256**                  – session-key derivation from the X25519
                                      shared secret.
- **AES-256-GCM**                   – authenticated encryption of payloads.

All primitives are provided by the ``cryptography`` package.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PublicFormat,
    PrivateFormat,
)
from cryptography.exceptions import InvalidSignature


class CryptoEngine:
    """
    Stateless helper that wraps all cryptographic operations used by ZTLNP.

    Instances hold no mutable state; all key material is passed in and out
    explicitly so that :class:`~ztlnp.device.Device` and
    :class:`~ztlnp.session.Session` remain the single sources of truth.
    """

    # ------------------------------------------------------------------
    # Ed25519 identity keys
    # ------------------------------------------------------------------

    @staticmethod
    def generate_identity_keypair() -> tuple[Ed25519PrivateKey, bytes]:
        """
        Generate a fresh Ed25519 identity key pair.

        Returns
        -------
        (private_key, public_key_bytes)
            The private key object and the raw 32-byte public key.
        """
        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = CryptoEngine.export_ed25519_public(private_key.public_key())
        return private_key, public_key_bytes

    @staticmethod
    def export_ed25519_public(public_key: Ed25519PublicKey) -> bytes:
        """Serialise an Ed25519 public key to 32 raw bytes."""
        return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @staticmethod
    def import_ed25519_public(raw: bytes) -> Ed25519PublicKey:
        """Deserialise 32 raw bytes into an Ed25519PublicKey object."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return Ed25519PublicKey.from_public_bytes(raw)

    @staticmethod
    def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
        """
        Sign *data* with an Ed25519 private key.

        Returns
        -------
        bytes
            64-byte signature.
        """
        return private_key.sign(data)

    @staticmethod
    def verify(public_key_bytes: bytes, data: bytes, signature: bytes) -> bool:
        """
        Verify an Ed25519 signature.

        Returns
        -------
        bool
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        try:
            pub = CryptoEngine.import_ed25519_public(public_key_bytes)
            pub.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    # ------------------------------------------------------------------
    # X25519 ephemeral key exchange
    # ------------------------------------------------------------------

    @staticmethod
    def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
        """
        Generate a fresh X25519 ephemeral key pair.

        Returns
        -------
        (private_key, public_key_bytes)
            The private key object and the raw 32-byte public key.
        """
        private_key = X25519PrivateKey.generate()
        public_key_bytes = CryptoEngine.export_x25519_public(private_key.public_key())
        return private_key, public_key_bytes

    @staticmethod
    def export_x25519_public(public_key: X25519PublicKey) -> bytes:
        """Serialise an X25519 public key to 32 raw bytes."""
        return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @staticmethod
    def import_x25519_public(raw: bytes) -> X25519PublicKey:
        """Deserialise 32 raw bytes into an X25519PublicKey object."""
        return X25519PublicKey.from_public_bytes(raw)

    @staticmethod
    def x25519_exchange(
        local_private: X25519PrivateKey, remote_public_bytes: bytes
    ) -> bytes:
        """
        Perform an X25519 Diffie-Hellman exchange.

        Returns
        -------
        bytes
            32-byte raw shared secret.
        """
        remote_pub = CryptoEngine.import_x25519_public(remote_public_bytes)
        return local_private.exchange(remote_pub)

    # ------------------------------------------------------------------
    # Session key derivation
    # ------------------------------------------------------------------

    @staticmethod
    def derive_session_key(
        shared_secret: bytes,
        initiator_id: bytes,
        responder_id: bytes,
    ) -> bytes:
        """
        Derive a 32-byte AES-256-GCM session key from an X25519 shared secret.

        HKDF-SHA-256 is used with a context string that binds the key to the
        specific pair of device identifiers, preventing key material from being
        reused across different sessions.

        Parameters
        ----------
        shared_secret:
            32-byte output of :meth:`x25519_exchange`.
        initiator_id:
            32-byte device identifier of the session initiator.
        responder_id:
            32-byte device identifier of the session responder.
        """
        info = b"ZTLNP-v1-session-key" + initiator_id + responder_id
        hkdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=info)
        return hkdf.derive(shared_secret)

    # ------------------------------------------------------------------
    # AES-256-GCM authenticated encryption
    # ------------------------------------------------------------------

    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a fresh 12-byte random nonce for AES-256-GCM."""
        return os.urandom(12)

    @staticmethod
    def encrypt(session_key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt *plaintext* with AES-256-GCM.

        Parameters
        ----------
        session_key:
            32-byte symmetric key.
        nonce:
            12-byte unique nonce.  **Must not be reused** with the same key.
        plaintext:
            Arbitrary bytes to encrypt.
        aad:
            Additional authenticated data (not encrypted, but authenticated).

        Returns
        -------
        bytes
            Ciphertext with a 16-byte GCM authentication tag appended.
        """
        aesgcm = AESGCM(session_key)
        return aesgcm.encrypt(nonce, plaintext, aad or None)

    @staticmethod
    def decrypt(session_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt and authenticate *ciphertext* with AES-256-GCM.

        Parameters
        ----------
        session_key:
            32-byte symmetric key.
        nonce:
            12-byte nonce used during encryption.
        ciphertext:
            Ciphertext with 16-byte authentication tag appended.
        aad:
            Additional authenticated data.

        Returns
        -------
        bytes
            Decrypted plaintext.

        Raises
        ------
        cryptography.exceptions.InvalidTag
            If authentication fails (ciphertext was tampered with).
        """
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(nonce, ciphertext, aad or None)

    # ------------------------------------------------------------------
    # Packet signing / verification helpers
    # ------------------------------------------------------------------

    @staticmethod
    def sign_packet(private_key: Ed25519PrivateKey, packet: "Packet") -> bytes:  # noqa: F821
        """Return the 64-byte Ed25519 signature over the packet's signed bytes."""
        return CryptoEngine.sign(private_key, packet.signed_bytes())

    @staticmethod
    def verify_packet(
        sender_ed25519_public_bytes: bytes, packet: "Packet"  # noqa: F821
    ) -> bool:
        """
        Verify the Ed25519 signature carried inside *packet*.

        The signature covers everything except the signature field itself
        (i.e. ``packet.signed_bytes()``).
        """
        return CryptoEngine.verify(
            sender_ed25519_public_bytes,
            packet.signed_bytes(),
            packet.signature,
        )
