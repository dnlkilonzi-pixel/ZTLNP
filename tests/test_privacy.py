"""
Tests for the ZTLNP privacy / traffic-analysis-resistance module.
"""

import time
import pytest

from ztlnp.privacy import (
    PaddingStrategy,
    pad_to_size,
    strip_padding,
    random_jitter_ms,
    jitter_sleep,
    CoverTraffic,
)
from ztlnp.device import Device
from ztlnp.protocol import Protocol, ProtocolState
from ztlnp.packet import PacketFlags


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def do_handshake(alice: Protocol, bob: Protocol) -> None:
    h1 = alice.initiate(bob.local.device_id)
    h2 = bob.process_incoming(h1)
    k1 = alice.process_incoming(h2)
    k2 = bob.process_incoming(k1)
    alice.process_incoming(k2)


# ---------------------------------------------------------------------------
# pad_to_size — FIXED strategy
# ---------------------------------------------------------------------------

class TestPadFixed:
    def test_pads_to_target(self):
        original = b"hello"
        padded, was_padded = pad_to_size(original, PaddingStrategy.FIXED, target_size=64)
        assert was_padded
        # padded = original + random_bytes + length_byte
        # length_byte = pad_len = target_size - len(original) - 1 = 58
        assert len(padded) == 64

    def test_no_pad_when_at_target(self):
        # exactly at target: needs to fit original + 1 length byte = target
        original = b"x" * 63
        padded, was_padded = pad_to_size(original, PaddingStrategy.FIXED, target_size=64)
        assert not was_padded
        assert padded == original

    def test_no_pad_when_above_target(self):
        original = b"x" * 100
        padded, was_padded = pad_to_size(original, PaddingStrategy.FIXED, target_size=64)
        assert not was_padded

    def test_last_byte_is_pad_len(self):
        original = b"data"
        padded, _ = pad_to_size(original, PaddingStrategy.FIXED, target_size=64)
        pad_len = padded[-1]
        assert len(original) + pad_len + 1 == 64

    def test_strip_roundtrip(self):
        original = b"important secret"
        padded, was_padded = pad_to_size(original, PaddingStrategy.FIXED, target_size=128)
        assert was_padded
        recovered = strip_padding(padded)
        assert recovered == original


# ---------------------------------------------------------------------------
# pad_to_size — RANDOM strategy
# ---------------------------------------------------------------------------

class TestPadRandom:
    def test_returns_same_or_larger(self):
        original = b"hello"
        for _ in range(20):
            padded, was_padded = pad_to_size(
                original, PaddingStrategy.RANDOM, max_pad=50
            )
            if was_padded:
                assert len(padded) > len(original)

    def test_strip_roundtrip(self):
        original = b"random padding test"
        # Force non-zero padding by using a large max_pad.
        for _ in range(10):
            padded, was_padded = pad_to_size(
                original, PaddingStrategy.RANDOM, max_pad=100
            )
            if was_padded:
                recovered = strip_padding(padded)
                assert recovered == original

    def test_pad_len_within_bounds(self):
        original = b"hi"
        for _ in range(20):
            padded, was_padded = pad_to_size(
                original, PaddingStrategy.RANDOM, max_pad=10
            )
            if was_padded:
                pad_len = padded[-1]
                assert 1 <= pad_len <= 10


# ---------------------------------------------------------------------------
# pad_to_size — BLOCK strategy
# ---------------------------------------------------------------------------

class TestPadBlock:
    def test_rounds_up_to_block(self):
        original = b"x" * 5  # 5 bytes
        # With block=8: 5 + 1 (length byte) = 6, next multiple of 8 is 8 → pad_len=2
        padded, was_padded = pad_to_size(
            original, PaddingStrategy.BLOCK, block_size=8
        )
        assert len(padded) % 8 == 0

    def test_already_aligned_no_pad(self):
        # 7 bytes + 1 length byte = 8 → already aligned
        original = b"x" * 7
        padded, was_padded = pad_to_size(
            original, PaddingStrategy.BLOCK, block_size=8
        )
        assert not was_padded

    def test_strip_roundtrip(self):
        original = b"block padding test"
        padded, was_padded = pad_to_size(
            original, PaddingStrategy.BLOCK, block_size=32
        )
        if was_padded:
            recovered = strip_padding(padded)
            assert recovered == original


# ---------------------------------------------------------------------------
# pad_to_size — NONE strategy
# ---------------------------------------------------------------------------

class TestPadNone:
    def test_no_modification(self):
        original = b"unchanged"
        padded, was_padded = pad_to_size(original, PaddingStrategy.NONE)
        assert not was_padded
        assert padded is original


# ---------------------------------------------------------------------------
# strip_padding edge cases
# ---------------------------------------------------------------------------

class TestStripPadding:
    def test_empty_data_raises(self):
        with pytest.raises(ValueError):
            strip_padding(b"")

    def test_pad_len_too_large_raises(self):
        # length byte claims 10 bytes of padding but only 5 bytes available total
        with pytest.raises(ValueError):
            strip_padding(b"\xAA\xBB\xCC\x0A")  # pad_len=10, only 3 bytes before it

    def test_zero_padding(self):
        # A valid pad_len=0 means just the length byte is stripped.
        data = b"hello" + bytes([0])  # 0 padding bytes, 1 length byte
        assert strip_padding(data) == b"hello"


# ---------------------------------------------------------------------------
# Timing jitter
# ---------------------------------------------------------------------------

class TestTimingJitter:
    def test_random_jitter_ms_in_range(self):
        for _ in range(50):
            j = random_jitter_ms(100.0)
            assert 0.0 <= j < 100.0

    def test_random_jitter_zero_max(self):
        assert random_jitter_ms(0.0) == 0.0
        assert random_jitter_ms(-5.0) == 0.0

    def test_jitter_sleep_returns_actual_delay(self):
        delay = jitter_sleep(10.0)  # Max 10 ms
        assert 0.0 <= delay <= 10.0

    def test_jitter_sleep_zero_is_instant(self):
        t0 = time.time()
        jitter_sleep(0.0)
        elapsed = (time.time() - t0) * 1000
        assert elapsed < 50  # well under 50 ms


# ---------------------------------------------------------------------------
# CoverTraffic
# ---------------------------------------------------------------------------

class TestCoverTraffic:
    def setup_method(self):
        alice_dev = Device("alice")
        bob_dev = Device("bob")
        self.alice = Protocol(alice_dev)
        self.bob = Protocol(bob_dev)
        do_handshake(self.alice, self.bob)

    def test_no_packet_before_interval(self):
        cover = CoverTraffic(self.alice, interval_ms=10_000.0)
        result = cover.maybe_send()
        assert result is None  # not enough time has elapsed

    def test_returns_packet_when_interval_elapsed(self):
        cover = CoverTraffic(self.alice, interval_ms=0.0)
        wire = cover.maybe_send()
        assert wire is not None
        assert len(wire) > 100

    def test_cover_packet_decryptable_by_peer(self):
        cover = CoverTraffic(self.alice, interval_ms=0.0, cover_payload_size=32)
        wire = cover.maybe_send()
        assert wire is not None
        # Bob can receive and decrypt it.
        plaintext = self.bob.receive_data(wire)
        assert len(plaintext) == 32

    def test_record_real_send_resets_timer(self):
        cover = CoverTraffic(self.alice, interval_ms=1.0)
        cover.record_real_send()
        result = cover.maybe_send()
        assert result is None  # just sent, shouldn't fire

    def test_interval_ms_property(self):
        cover = CoverTraffic(self.alice, interval_ms=500.0)
        assert cover.interval_ms == 500.0
        cover.interval_ms = 1000.0
        assert cover.interval_ms == 1000.0

    def test_interval_ms_zero_raises(self):
        cover = CoverTraffic(self.alice, interval_ms=500.0)
        with pytest.raises(ValueError):
            cover.interval_ms = 0.0

    def test_cover_traffic_uses_mac_by_default(self):
        cover = CoverTraffic(self.alice, interval_ms=0.0, use_mac=True)
        wire = cover.maybe_send()
        assert wire is not None
        # MAC_AUTH flag should be set when use_mac=True.
        flags = int.from_bytes(wire[6:8], "big")
        assert flags & PacketFlags.MAC_AUTH

    def test_cover_traffic_no_mac(self):
        cover = CoverTraffic(self.alice, interval_ms=0.0, use_mac=False)
        wire = cover.maybe_send()
        assert wire is not None
        plaintext = self.bob.receive_data(wire)
        assert len(plaintext) > 0


# ---------------------------------------------------------------------------
# Route poisoning defence (TrustStore + Router integration)
# ---------------------------------------------------------------------------

class TestTrustPoisoningDefence:
    def test_endorsement_depth_limit(self):
        from ztlnp.trust import TrustStore, TrustLevel
        from ztlnp.trust import create_endorsement
        from ztlnp.exceptions import TrustPoisoningError
        import hashlib

        # max_endorsement_depth=1: only one hop of endorsement allowed
        store = TrustStore(max_endorsement_depth=1)

        def add_verified(pub):
            store.add(pub, TrustLevel.VERIFIED)

        a_priv, a_pub, a_id = _make_keys()
        b_priv, b_pub, b_id = _make_keys()
        c_priv, c_pub, c_id = _make_keys()
        d_priv, d_pub, d_id = _make_keys()

        add_verified(a_pub)  # depth=0

        # A endorses B → B at depth=1 (OK)
        blob_ab = create_endorsement(a_priv, a_id, b_id, b_pub)
        store.add_endorsement(blob_ab, a_id)
        assert store.get(b_id).endorsement_depth == 1

        # B endorses C → depth would be 2, exceeds max of 1 → REJECTED
        # B must first be VERIFIED to endorse, but its trust_level=ENDORSED
        # The endorsement depth check fires first.
        store.get(b_id).trust_level = TrustLevel.VERIFIED  # simulate upgrade
        blob_bc = create_endorsement(b_priv, b_id, c_id, c_pub)
        with pytest.raises(TrustPoisoningError, match="depth"):
            store.add_endorsement(blob_bc, b_id)

    def test_distrust_blacklists_device(self):
        from ztlnp.trust import TrustStore, TrustLevel
        store = TrustStore()
        _, pub, dev_id = _make_keys()
        store.add(pub, TrustLevel.VERIFIED)
        assert store.is_trusted(dev_id)

        store.distrust(dev_id)
        assert not store.is_trusted(dev_id)
        assert store.is_blacklisted(dev_id)

    def test_remove_blacklist_restores_trust(self):
        from ztlnp.trust import TrustStore, TrustLevel
        store = TrustStore()
        _, pub, dev_id = _make_keys()
        store.add(pub, TrustLevel.VERIFIED)
        store.distrust(dev_id)
        store.remove_blacklist(dev_id)
        assert store.is_trusted(dev_id)

    def test_trust_cap_on_route_announcements(self):
        from ztlnp.router import Router
        from ztlnp.transport import InProcessTransport
        import struct

        router = Router(b"\xAA" * 32, max_advertised_trust=0.5)
        t, _ = InProcessTransport.create_pair()

        # Attacker claims trust_score=1.0 but cap is 0.5
        payload = struct.pack("!32sH", b"\xBB" * 32, 0)  # 0 hops
        updated = router.process_announce_payload(payload, t, b"evil", sender_trust_score=1.0)
        assert len(updated) == 1
        # trust_score must not exceed cap × decay
        assert updated[0].trust_score <= 0.5

    def test_max_advertised_trust_property(self):
        from ztlnp.router import Router
        router = Router(b"\xAA" * 32, max_advertised_trust=0.7)
        assert router.max_advertised_trust == 0.7

    def test_trust_cap_clamped_to_0_1(self):
        from ztlnp.router import Router
        r1 = Router(b"\xAA" * 32, max_advertised_trust=1.5)
        assert r1.max_advertised_trust == 1.0
        r2 = Router(b"\xAA" * 32, max_advertised_trust=-0.3)
        assert r2.max_advertised_trust == 0.0


def _make_keys():
    from ztlnp.crypto import CryptoEngine
    import hashlib
    priv, pub = CryptoEngine.generate_identity_keypair()
    return priv, pub, hashlib.sha256(pub).digest()
