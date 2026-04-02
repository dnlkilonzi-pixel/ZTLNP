"""
Tests for the ZTLNP forward-secure identity rotation system.
"""

import hashlib
import time
import pytest

from ztlnp.device import Device
from ztlnp.identity import (
    KeyTransition,
    RotationManager,
    RotationRecord,
    TRANSITION_SIZE,
    create_key_transition,
)
from ztlnp.trust import TrustLevel, TrustStore
from ztlnp.crypto import CryptoEngine
from ztlnp.exceptions import KeyRotationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_device_key():
    priv, pub = CryptoEngine.generate_identity_keypair()
    device_id = hashlib.sha256(pub).digest()
    return priv, pub, device_id


# ---------------------------------------------------------------------------
# KeyTransition serialisation
# ---------------------------------------------------------------------------

class TestKeyTransition:
    def test_roundtrip(self):
        old_priv, old_pub, old_id = make_device_key()
        _, new_pub, _ = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        data = t.to_bytes()
        assert len(data) == TRANSITION_SIZE
        t2 = KeyTransition.from_bytes(data)
        assert t2.old_device_id == t.old_device_id
        assert t2.new_device_id == t.new_device_id
        assert t2.new_ed25519_public == t.new_ed25519_public
        assert t2.timestamp_ms == t.timestamp_ms
        assert t2.signature == t.signature

    def test_wrong_size_raises(self):
        with pytest.raises(KeyRotationError, match="bytes"):
            KeyTransition.from_bytes(b"\x00" * 100)

    def test_new_device_id_matches_pub(self):
        old_priv, old_pub, old_id = make_device_key()
        _, new_pub, _ = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        assert t.new_device_id == hashlib.sha256(new_pub).digest()

    def test_field_length_validation(self):
        old_priv, old_pub, old_id = make_device_key()
        _, new_pub, new_id = make_device_key()
        with pytest.raises(ValueError):
            KeyTransition(
                old_device_id=b"\x00" * 31,  # wrong length
                new_device_id=new_id,
                new_ed25519_public=new_pub,
                timestamp_ms=int(time.time() * 1000),
                signature=b"\x00" * 64,
            )


# ---------------------------------------------------------------------------
# RotationManager — happy path
# ---------------------------------------------------------------------------

class TestRotationManagerHappyPath:
    def setup_method(self):
        self.store = TrustStore(allow_tofu=True)
        self.mgr = RotationManager(self.store, max_rotations=10)

    def test_apply_transition_migrates_trust(self):
        old_priv, old_pub, old_id = make_device_key()
        self.store.add(old_pub, TrustLevel.VERIFIED)

        _, new_pub, new_id = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        self.mgr.apply_transition(t)

        assert self.store.is_trusted(new_id)
        assert self.store.get(new_id).trust_level == TrustLevel.VERIFIED

    def test_apply_preserves_endorsers(self):
        old_priv, old_pub, old_id = make_device_key()
        endorser_id = b"\xEE" * 32
        self.store.add(old_pub, TrustLevel.ENDORSED)
        self.store.get(old_id).endorsers.append(endorser_id)

        _, new_pub, new_id = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        self.mgr.apply_transition(t)

        new_rec = self.store.get(new_id)
        assert endorser_id in new_rec.endorsers

    def test_resolve_follows_chain(self):
        old_priv, old_pub, old_id = make_device_key()
        self.store.add(old_pub, TrustLevel.VERIFIED)

        new_priv, new_pub, new_id = make_device_key()
        t1 = create_key_transition(old_priv, old_id, new_pub)
        self.mgr.apply_transition(t1)

        # Second rotation.
        _, new_pub2, new_id2 = make_device_key()
        t2 = create_key_transition(new_priv, new_id, new_pub2)
        self.mgr.apply_transition(t2)

        assert self.mgr.resolve(old_id) == new_id2
        assert self.mgr.resolve(new_id) == new_id2
        assert self.mgr.resolve(new_id2) == new_id2

    def test_rotation_history(self):
        old_priv, old_pub, old_id = make_device_key()
        self.store.add(old_pub, TrustLevel.VERIFIED)

        _, new_pub, new_id = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        self.mgr.apply_transition(t)

        history = self.mgr.rotation_history(new_id)
        assert len(history) == 1
        assert history[0].old_device_id == old_id
        assert history[0].new_device_id == new_id

    def test_is_retired(self):
        old_priv, old_pub, old_id = make_device_key()
        self.store.add(old_pub, TrustLevel.VERIFIED)
        _, new_pub, _ = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        self.mgr.apply_transition(t)

        assert self.mgr.is_retired(old_id)
        assert not self.mgr.is_retired(b"\x00" * 32)

    def test_rotation_count_increments(self):
        old_priv, old_pub, old_id = make_device_key()
        self.store.add(old_pub, TrustLevel.VERIFIED)
        _, new_pub, new_id = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        self.mgr.apply_transition(t)
        assert self.mgr.rotation_count(new_id) == 1

    def test_rotation_count_zero_for_fresh_device(self):
        assert self.mgr.rotation_count(b"\x00" * 32) == 0


# ---------------------------------------------------------------------------
# RotationManager — error cases
# ---------------------------------------------------------------------------

class TestRotationManagerErrors:
    def setup_method(self):
        self.store = TrustStore()
        self.mgr = RotationManager(self.store, max_rotations=3)

    def test_unknown_old_device_raises(self):
        old_priv, old_pub, old_id = make_device_key()
        _, new_pub, _ = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        with pytest.raises(KeyRotationError, match="Unknown"):
            self.mgr.apply_transition(t)

    def test_bad_signature_raises(self):
        old_priv, old_pub, old_id = make_device_key()
        self.store.add(old_pub, TrustLevel.VERIFIED)
        _, new_pub, new_id = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        # Tamper with a byte inside the Ed25519 signature (bytes 104+).
        # The body (old_id, new_id, new_pub, timestamp) is left intact so
        # the early validation checks pass; only the signature itself is bad.
        data = bytearray(t.to_bytes())
        data[110] ^= 0xFF  # signature region starts at offset 104
        t2 = KeyTransition.from_bytes(bytes(data))
        with pytest.raises(KeyRotationError, match="signature"):
            self.mgr.apply_transition(t2)

    def test_future_timestamp_raises(self):
        old_priv, old_pub, old_id = make_device_key()
        self.store.add(old_pub, TrustLevel.VERIFIED)
        _, new_pub, new_id = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        # Push timestamp 60 s into the future.
        future_ts = t.timestamp_ms + 60_000
        import struct
        body = struct.pack("!32s32s32sQ",
                           t.old_device_id, t.new_device_id,
                           t.new_ed25519_public, future_ts)
        sig = CryptoEngine.sign(old_priv, body)
        bad_t = KeyTransition(
            old_device_id=t.old_device_id,
            new_device_id=t.new_device_id,
            new_ed25519_public=t.new_ed25519_public,
            timestamp_ms=future_ts,
            signature=sig,
        )
        with pytest.raises(KeyRotationError, match="future"):
            self.mgr.apply_transition(bad_t)

    def test_replay_old_timestamp_raises(self):
        old_priv, old_pub, old_id = make_device_key()
        self.store.add(old_pub, TrustLevel.VERIFIED)
        _, new_pub, new_id = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        self.mgr.apply_transition(t)  # first application succeeds

        # Re-apply the same transition (replay).
        with pytest.raises(KeyRotationError, match="replay"):
            self.mgr.apply_transition(t)

    def test_max_rotations_enforced(self):
        old_priv, old_pub, old_id = make_device_key()
        self.store.add(old_pub, TrustLevel.VERIFIED)

        current_priv = old_priv
        current_id = old_id

        for _ in range(3):
            new_priv, new_pub, new_id = make_device_key()
            t = create_key_transition(current_priv, current_id, new_pub)
            self.mgr.apply_transition(t)
            current_priv, current_id = new_priv, new_id

        # 4th rotation should fail.
        _, final_pub, _ = make_device_key()
        t_over = create_key_transition(current_priv, current_id, final_pub)
        with pytest.raises(KeyRotationError, match="rotation budget"):
            self.mgr.apply_transition(t_over)

    def test_new_device_id_mismatch_raises(self):
        old_priv, old_pub, old_id = make_device_key()
        self.store.add(old_pub, TrustLevel.VERIFIED)
        _, new_pub, new_id = make_device_key()
        t = create_key_transition(old_priv, old_id, new_pub)
        # Forge a wrong new_device_id in the transition.
        wrong_new_id = b"\xAB" * 32
        tampered = KeyTransition(
            old_device_id=t.old_device_id,
            new_device_id=wrong_new_id,
            new_ed25519_public=t.new_ed25519_public,
            timestamp_ms=t.timestamp_ms,
            signature=t.signature,
        )
        with pytest.raises(KeyRotationError, match="new_device_id"):
            self.mgr.apply_transition(tampered)


# ---------------------------------------------------------------------------
# Device.rotate_key() integration
# ---------------------------------------------------------------------------

class TestDeviceRotateKey:
    def test_rotate_changes_device_id(self):
        dev = Device("rotater")
        old_id = dev.device_id
        dev.rotate_key()
        assert dev.device_id != old_id

    def test_rotate_returns_valid_transition(self):
        dev = Device("rotater")
        old_id = dev.device_id
        old_pub = dev.identity_public_bytes
        transition = dev.rotate_key()
        assert transition.old_device_id == old_id
        assert transition.new_device_id == dev.device_id
        assert transition.new_ed25519_public == dev.identity_public_bytes
        assert len(transition.signature) == 64

    def test_rotate_transition_verifiable_by_manager(self):
        dev = Device("rotater")
        store = TrustStore()
        mgr = RotationManager(store, max_rotations=5)
        # Register the original key.
        store.add(dev.identity_public_bytes, TrustLevel.VERIFIED)
        old_id = dev.device_id

        transition = dev.rotate_key()
        mgr.apply_transition(transition)

        assert store.is_trusted(dev.device_id)
        assert mgr.is_retired(old_id)

    def test_multiple_rotations(self):
        dev = Device("serial-rotater")
        store = TrustStore()
        mgr = RotationManager(store, max_rotations=5)
        store.add(dev.identity_public_bytes, TrustLevel.VERIFIED)

        ids = [dev.device_id]
        for _ in range(3):
            t = dev.rotate_key()
            mgr.apply_transition(t)
            ids.append(dev.device_id)

        # All old IDs should be retired.
        for old in ids[:-1]:
            assert mgr.is_retired(old)
        assert store.is_trusted(dev.device_id)
