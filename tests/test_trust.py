"""
Tests for the ZTLNP trust bootstrap layer.
"""

import hashlib
import pytest

from ztlnp.trust import (
    TrustLevel,
    TrustRecord,
    TrustStore,
    fingerprint_of,
    encode_qr_payload,
    parse_qr_payload,
    create_endorsement,
)
from ztlnp.crypto import CryptoEngine
from ztlnp.exceptions import TrustError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_device():
    priv, pub = CryptoEngine.generate_identity_keypair()
    device_id = hashlib.sha256(pub).digest()
    return priv, pub, device_id


# ---------------------------------------------------------------------------
# TrustRecord
# ---------------------------------------------------------------------------

class TestTrustRecord:
    def test_valid_record(self):
        _, pub, dev_id = make_device()
        rec = TrustRecord(device_id=dev_id, ed25519_public=pub)
        assert rec.trust_level == TrustLevel.TOFU
        assert rec.endorsers == []

    def test_device_id_mismatch_raises(self):
        _, pub, _ = make_device()
        bad_id = b"\xFF" * 32
        with pytest.raises(TrustError, match="device_id"):
            TrustRecord(device_id=bad_id, ed25519_public=pub)

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError):
            TrustRecord(device_id=b"\x00" * 31, ed25519_public=b"\x00" * 32)


# ---------------------------------------------------------------------------
# TrustStore – TOFU
# ---------------------------------------------------------------------------

class TestTrustStoreTOFU:
    def test_add_and_retrieve(self):
        store = TrustStore()
        _, pub, dev_id = make_device()
        rec = store.add(pub)
        assert rec.device_id == dev_id
        assert rec.trust_level == TrustLevel.TOFU
        assert store.is_trusted(dev_id)

    def test_get_public_key(self):
        store = TrustStore()
        _, pub, dev_id = make_device()
        store.add(pub)
        assert store.get_public_key(dev_id) == pub

    def test_get_public_key_unknown_raises(self):
        store = TrustStore()
        with pytest.raises(TrustError, match="Unknown device"):
            store.get_public_key(b"\x00" * 32)

    def test_add_upgrades_trust_level(self):
        store = TrustStore()
        _, pub, dev_id = make_device()
        store.add(pub, TrustLevel.TOFU)
        store.add(pub, TrustLevel.VERIFIED)
        assert store.get(dev_id).trust_level == TrustLevel.VERIFIED

    def test_add_does_not_downgrade(self):
        store = TrustStore()
        _, pub, dev_id = make_device()
        store.add(pub, TrustLevel.VERIFIED)
        store.add(pub, TrustLevel.TOFU)
        assert store.get(dev_id).trust_level == TrustLevel.VERIFIED

    def test_is_trusted_unknown_is_false(self):
        store = TrustStore()
        assert not store.is_trusted(b"\x01" * 32)

    def test_min_trust_filters_tofu(self):
        store = TrustStore(min_trust=TrustLevel.VERIFIED)
        _, pub, dev_id = make_device()
        store.add(pub, TrustLevel.TOFU)
        assert not store.is_trusted(dev_id)


# ---------------------------------------------------------------------------
# TrustStore – process_hello
# ---------------------------------------------------------------------------

class TestProcessHello:
    def test_tofu_accepted(self):
        store = TrustStore(allow_tofu=True)
        _, pub, dev_id = make_device()
        rec = store.process_hello(dev_id, pub)
        assert rec.trust_level == TrustLevel.TOFU

    def test_tofu_disabled_raises(self):
        store = TrustStore(allow_tofu=False)
        _, pub, dev_id = make_device()
        with pytest.raises(TrustError, match="TOFU is disabled"):
            store.process_hello(dev_id, pub)

    def test_known_device_same_key_ok(self):
        store = TrustStore()
        _, pub, dev_id = make_device()
        store.add(pub)
        rec = store.process_hello(dev_id, pub)
        assert rec.device_id == dev_id

    def test_known_device_different_key_raises(self):
        store = TrustStore()
        _, pub1, dev_id = make_device()
        _, pub2, _ = make_device()
        store.add(pub1)
        # Pretend attacker sends pub2 but claims it's dev_id.
        with pytest.raises(TrustError, match="mismatch"):
            store.process_hello(dev_id, pub2)


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

class TestFingerprint:
    def test_format(self):
        _, pub, _ = make_device()
        fp = fingerprint_of(pub)
        groups = fp.split(":")
        assert len(groups) == 16
        assert all(len(g) == 4 for g in groups)
        assert fp == fp.upper()

    def test_deterministic(self):
        _, pub, _ = make_device()
        assert fingerprint_of(pub) == fingerprint_of(pub)

    def test_different_keys_different_fingerprints(self):
        _, pub1, _ = make_device()
        _, pub2, _ = make_device()
        assert fingerprint_of(pub1) != fingerprint_of(pub2)

    def test_verify_fingerprint_upgrades_trust(self):
        store = TrustStore()
        _, pub, dev_id = make_device()
        store.add(pub, TrustLevel.TOFU)
        fp = fingerprint_of(pub)
        result = store.verify_fingerprint(dev_id, fp)
        assert result
        assert store.get(dev_id).trust_level == TrustLevel.VERIFIED

    def test_verify_wrong_fingerprint_returns_false(self):
        store = TrustStore()
        _, pub, dev_id = make_device()
        store.add(pub)
        assert not store.verify_fingerprint(dev_id, "0000:0000:0000:0000:0000:0000:0000:0000")

    def test_verify_unknown_device_returns_false(self):
        store = TrustStore()
        assert not store.verify_fingerprint(b"\x00" * 32, "AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:0000:1111")


# ---------------------------------------------------------------------------
# QR payload
# ---------------------------------------------------------------------------

class TestQRPayload:
    def test_encode_decode_roundtrip(self):
        _, pub, dev_id = make_device()
        payload = encode_qr_payload(dev_id, pub)
        recovered_id, recovered_pub = parse_qr_payload(payload)
        assert recovered_id == dev_id
        assert recovered_pub == pub

    def test_payload_starts_with_ztlnp(self):
        _, pub, dev_id = make_device()
        assert encode_qr_payload(dev_id, pub).startswith("ZTLNP:1:")

    def test_parse_invalid_format_raises(self):
        with pytest.raises(TrustError):
            parse_qr_payload("NOT:A:VALID:PAYLOAD")

    def test_parse_tampered_fingerprint_raises(self):
        _, pub, dev_id = make_device()
        payload = encode_qr_payload(dev_id, pub)
        parts = payload.split(":")
        parts[-1] = "00" * 32   # bad fingerprint
        with pytest.raises(TrustError):
            parse_qr_payload(":".join(parts))

    def test_qr_store_integration(self):
        """Round-trip through QR payload and add to TrustStore as VERIFIED."""
        store = TrustStore()
        _, pub, dev_id = make_device()
        payload = encode_qr_payload(dev_id, pub)
        _, recovered_pub = parse_qr_payload(payload)
        store.add(recovered_pub, TrustLevel.VERIFIED)
        assert store.is_trusted(dev_id)
        assert store.get(dev_id).trust_level == TrustLevel.VERIFIED


# ---------------------------------------------------------------------------
# Web-of-trust endorsements
# ---------------------------------------------------------------------------

class TestWebOfTrust:
    def test_create_and_verify_endorsement(self):
        endorser_priv, endorser_pub, endorser_id = make_device()
        _, target_pub, target_id = make_device()

        store = TrustStore()
        store.add(endorser_pub, TrustLevel.VERIFIED)  # endorser must be VERIFIED

        blob = create_endorsement(endorser_priv, endorser_id, target_id, target_pub)
        assert len(blob) == 160

        rec = store.add_endorsement(blob, endorser_id)
        assert rec.trust_level == TrustLevel.ENDORSED
        assert endorser_id in rec.endorsers

    def test_unverified_endorser_raises(self):
        endorser_priv, endorser_pub, endorser_id = make_device()
        _, target_pub, target_id = make_device()

        store = TrustStore()
        store.add(endorser_pub, TrustLevel.TOFU)  # only TOFU — not enough

        blob = create_endorsement(endorser_priv, endorser_id, target_id, target_pub)
        with pytest.raises(TrustError, match="not VERIFIED"):
            store.add_endorsement(blob, endorser_id)

    def test_unknown_endorser_raises(self):
        endorser_priv, endorser_pub, endorser_id = make_device()
        _, target_pub, target_id = make_device()

        store = TrustStore()
        # Do NOT add endorser to the store.
        blob = create_endorsement(endorser_priv, endorser_id, target_id, target_pub)
        with pytest.raises(TrustError, match="unknown"):
            store.add_endorsement(blob, endorser_id)

    def test_tampered_endorsement_raises(self):
        endorser_priv, endorser_pub, endorser_id = make_device()
        _, target_pub, target_id = make_device()

        store = TrustStore()
        store.add(endorser_pub, TrustLevel.VERIFIED)

        blob = bytearray(create_endorsement(endorser_priv, endorser_id, target_id, target_pub))
        blob[50] ^= 0xFF  # tamper
        with pytest.raises(TrustError, match="signature"):
            store.add_endorsement(bytes(blob), endorser_id)

    def test_wrong_blob_length_raises(self):
        endorser_priv, endorser_pub, endorser_id = make_device()
        store = TrustStore()
        store.add(endorser_pub, TrustLevel.VERIFIED)
        with pytest.raises(TrustError, match="bytes"):
            store.add_endorsement(b"\x00" * 50, endorser_id)

    def test_transitive_endorsement(self):
        """Chain: Alice (VERIFIED) endorses Bob; Bob should become ENDORSED."""
        alice_priv, alice_pub, alice_id = make_device()
        _, bob_pub, bob_id = make_device()

        store = TrustStore()
        store.add(alice_pub, TrustLevel.VERIFIED)

        blob = create_endorsement(alice_priv, alice_id, bob_id, bob_pub)
        rec = store.add_endorsement(blob, alice_id)
        assert rec.trust_level == TrustLevel.ENDORSED
        assert store.is_trusted(bob_id)
