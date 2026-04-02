"""
Tests for the ZTLNP cryptographic engine.
"""

import pytest

from ztlnp.crypto import CryptoEngine
from ztlnp.packet import Packet, PacketType, PacketFlags
from ztlnp.exceptions import SignatureVerificationError

SENDER_ID = b"\xAA" * 32


# ---------------------------------------------------------------------------
# Ed25519 identity keys
# ---------------------------------------------------------------------------

class TestEd25519:
    def test_generate_keypair_returns_32_byte_pubkey(self):
        _, pub = CryptoEngine.generate_identity_keypair()
        assert isinstance(pub, bytes)
        assert len(pub) == 32

    def test_sign_verify_roundtrip(self):
        priv, pub = CryptoEngine.generate_identity_keypair()
        data = b"zero trust payload"
        sig = CryptoEngine.sign(priv, data)
        assert len(sig) == 64
        assert CryptoEngine.verify(pub, data, sig)

    def test_verify_with_wrong_key_returns_false(self):
        priv, _ = CryptoEngine.generate_identity_keypair()
        _, other_pub = CryptoEngine.generate_identity_keypair()
        sig = CryptoEngine.sign(priv, b"data")
        assert not CryptoEngine.verify(other_pub, b"data", sig)

    def test_verify_with_tampered_data_returns_false(self):
        priv, pub = CryptoEngine.generate_identity_keypair()
        sig = CryptoEngine.sign(priv, b"original")
        assert not CryptoEngine.verify(pub, b"tampered", sig)

    def test_verify_with_truncated_sig_returns_false(self):
        priv, pub = CryptoEngine.generate_identity_keypair()
        sig = CryptoEngine.sign(priv, b"data")
        assert not CryptoEngine.verify(pub, b"data", sig[:32] + b"\x00" * 32)

    def test_export_import_public_key_roundtrip(self):
        priv, pub_bytes = CryptoEngine.generate_identity_keypair()
        pub_obj = CryptoEngine.import_ed25519_public(pub_bytes)
        assert CryptoEngine.export_ed25519_public(pub_obj) == pub_bytes


# ---------------------------------------------------------------------------
# X25519 key exchange
# ---------------------------------------------------------------------------

class TestX25519:
    def test_generate_keypair_returns_32_byte_pubkey(self):
        _, pub = CryptoEngine.generate_x25519_keypair()
        assert isinstance(pub, bytes)
        assert len(pub) == 32

    def test_exchange_produces_same_secret_on_both_sides(self):
        priv_a, pub_a = CryptoEngine.generate_x25519_keypair()
        priv_b, pub_b = CryptoEngine.generate_x25519_keypair()
        secret_a = CryptoEngine.x25519_exchange(priv_a, pub_b)
        secret_b = CryptoEngine.x25519_exchange(priv_b, pub_a)
        assert secret_a == secret_b
        assert len(secret_a) == 32

    def test_different_keypairs_produce_different_secrets(self):
        priv_a, _ = CryptoEngine.generate_x25519_keypair()
        priv_b, pub_b = CryptoEngine.generate_x25519_keypair()
        priv_c, pub_c = CryptoEngine.generate_x25519_keypair()
        secret_ab = CryptoEngine.x25519_exchange(priv_a, pub_b)
        secret_ac = CryptoEngine.x25519_exchange(priv_a, pub_c)
        assert secret_ab != secret_ac


# ---------------------------------------------------------------------------
# HKDF session-key derivation
# ---------------------------------------------------------------------------

class TestSessionKeyDerivation:
    def test_derive_returns_32_bytes(self):
        key = CryptoEngine.derive_session_key(b"\x00" * 32, b"\x01" * 32, b"\x02" * 32)
        assert len(key) == 32

    def test_same_inputs_produce_same_key(self):
        shared = b"\xAB" * 32
        init_id = b"\x01" * 32
        resp_id = b"\x02" * 32
        k1 = CryptoEngine.derive_session_key(shared, init_id, resp_id)
        k2 = CryptoEngine.derive_session_key(shared, init_id, resp_id)
        assert k1 == k2

    def test_swapped_ids_produce_different_keys(self):
        shared = b"\xAB" * 32
        id_a = b"\x01" * 32
        id_b = b"\x02" * 32
        k1 = CryptoEngine.derive_session_key(shared, id_a, id_b)
        k2 = CryptoEngine.derive_session_key(shared, id_b, id_a)
        assert k1 != k2

    def test_both_sides_derive_same_key(self):
        priv_a, pub_a = CryptoEngine.generate_x25519_keypair()
        priv_b, pub_b = CryptoEngine.generate_x25519_keypair()
        id_a = b"\x01" * 32
        id_b = b"\x02" * 32
        shared_a = CryptoEngine.x25519_exchange(priv_a, pub_b)
        shared_b = CryptoEngine.x25519_exchange(priv_b, pub_a)
        key_a = CryptoEngine.derive_session_key(shared_a, id_a, id_b)
        key_b = CryptoEngine.derive_session_key(shared_b, id_a, id_b)
        assert key_a == key_b


# ---------------------------------------------------------------------------
# AES-256-GCM encryption / decryption
# ---------------------------------------------------------------------------

class TestAESGCM:
    def _key(self) -> bytes:
        return b"\x55" * 32

    def _nonce(self) -> bytes:
        return b"\x66" * 12

    def test_encrypt_decrypt_roundtrip(self):
        key, nonce = self._key(), self._nonce()
        plaintext = b"secret zero-trust message"
        ct = CryptoEngine.encrypt(key, nonce, plaintext)
        assert CryptoEngine.decrypt(key, nonce, ct) == plaintext

    def test_empty_plaintext(self):
        key, nonce = self._key(), self._nonce()
        ct = CryptoEngine.encrypt(key, nonce, b"")
        assert CryptoEngine.decrypt(key, nonce, ct) == b""

    def test_ciphertext_differs_from_plaintext(self):
        key, nonce = self._key(), self._nonce()
        plaintext = b"plaintext"
        ct = CryptoEngine.encrypt(key, nonce, plaintext)
        assert ct != plaintext

    def test_tampered_ciphertext_raises(self):
        from cryptography.exceptions import InvalidTag
        key, nonce = self._key(), self._nonce()
        ct = bytearray(CryptoEngine.encrypt(key, nonce, b"data"))
        ct[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            CryptoEngine.decrypt(key, nonce, bytes(ct))

    def test_wrong_key_raises(self):
        from cryptography.exceptions import InvalidTag
        nonce = self._nonce()
        ct = CryptoEngine.encrypt(self._key(), nonce, b"data")
        with pytest.raises(InvalidTag):
            CryptoEngine.decrypt(b"\x00" * 32, nonce, ct)

    def test_aad_roundtrip(self):
        key, nonce = self._key(), self._nonce()
        plaintext, aad = b"message", b"authenticated header"
        ct = CryptoEngine.encrypt(key, nonce, plaintext, aad)
        assert CryptoEngine.decrypt(key, nonce, ct, aad) == plaintext

    def test_wrong_aad_raises(self):
        from cryptography.exceptions import InvalidTag
        key, nonce = self._key(), self._nonce()
        ct = CryptoEngine.encrypt(key, nonce, b"data", b"correct aad")
        with pytest.raises(InvalidTag):
            CryptoEngine.decrypt(key, nonce, ct, b"wrong aad")

    def test_generate_nonce_is_random(self):
        nonces = {CryptoEngine.generate_nonce() for _ in range(100)}
        assert len(nonces) == 100


# ---------------------------------------------------------------------------
# Packet signing helpers
# ---------------------------------------------------------------------------

class TestPacketSigning:
    def test_sign_and_verify_packet(self):
        priv, pub = CryptoEngine.generate_identity_keypair()
        packet = Packet(
            ptype=PacketType.DATA,
            sender_id=SENDER_ID,
            payload=b"test",
            timestamp_ms=1,
        )
        packet.signature = CryptoEngine.sign_packet(priv, packet)
        assert CryptoEngine.verify_packet(pub, packet)

    def test_verify_packet_with_wrong_key_fails(self):
        priv, _ = CryptoEngine.generate_identity_keypair()
        _, other_pub = CryptoEngine.generate_identity_keypair()
        packet = Packet(
            ptype=PacketType.DATA,
            sender_id=SENDER_ID,
            payload=b"test",
            timestamp_ms=1,
        )
        packet.signature = CryptoEngine.sign_packet(priv, packet)
        assert not CryptoEngine.verify_packet(other_pub, packet)

    def test_verify_packet_after_payload_tamper_fails(self):
        priv, pub = CryptoEngine.generate_identity_keypair()
        packet = Packet(
            ptype=PacketType.DATA,
            sender_id=SENDER_ID,
            payload=b"original",
            timestamp_ms=1,
        )
        packet.signature = CryptoEngine.sign_packet(priv, packet)
        # Tamper with the payload after signing.
        packet.payload = b"tampered"
        assert not CryptoEngine.verify_packet(pub, packet)
