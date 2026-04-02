"""
Tests for the ZTLNP routing layer.
"""

import pytest

from ztlnp.router import Router, RouteTable, RouteEntry
from ztlnp.transport import InProcessTransport
from ztlnp.exceptions import RoutingError


DEVICE_A = b"\xAA" * 32
DEVICE_B = b"\xBB" * 32
DEVICE_C = b"\xCC" * 32


def make_transport():
    a, b = InProcessTransport.create_pair(b"alpha", b"beta")
    return a, b


# ---------------------------------------------------------------------------
# RouteEntry
# ---------------------------------------------------------------------------

class TestRouteEntry:
    def test_score_increases_with_trust(self):
        t, _ = make_transport()
        low = RouteEntry(DEVICE_B, t, b"beta", hop_count=1, trust_score=0.1, latency_ms=1.0)
        high = RouteEntry(DEVICE_B, t, b"beta", hop_count=1, trust_score=1.0, latency_ms=1.0)
        assert high.score > low.score

    def test_score_decreases_with_hops(self):
        t, _ = make_transport()
        direct = RouteEntry(DEVICE_B, t, b"beta", hop_count=1, trust_score=1.0, latency_ms=1.0)
        multi = RouteEntry(DEVICE_B, t, b"beta", hop_count=5, trust_score=1.0, latency_ms=1.0)
        assert direct.score > multi.score

    def test_score_decreases_with_latency(self):
        t, _ = make_transport()
        fast = RouteEntry(DEVICE_B, t, b"beta", hop_count=1, trust_score=1.0, latency_ms=1.0)
        slow = RouteEntry(DEVICE_B, t, b"beta", hop_count=1, trust_score=1.0, latency_ms=100.0)
        assert fast.score > slow.score


# ---------------------------------------------------------------------------
# RouteTable
# ---------------------------------------------------------------------------

class TestRouteTable:
    def test_add_and_best(self):
        table = RouteTable()
        t, _ = make_transport()
        entry = RouteEntry(DEVICE_B, t, b"beta", hop_count=1, trust_score=1.0)
        table.add(entry)
        assert table.best(DEVICE_B) is entry

    def test_best_prefers_highest_score(self):
        table = RouteTable()
        t, _ = make_transport()
        low = RouteEntry(DEVICE_B, t, b"beta1", hop_count=3, trust_score=0.5, latency_ms=10.0)
        high = RouteEntry(DEVICE_B, t, b"beta2", hop_count=1, trust_score=1.0, latency_ms=1.0)
        table.add(low)
        table.add(high)
        assert table.best(DEVICE_B).score == high.score

    def test_best_unknown_returns_none(self):
        table = RouteTable()
        assert table.best(DEVICE_C) is None

    def test_update_existing_route(self):
        table = RouteTable()
        t, _ = make_transport()
        e1 = RouteEntry(DEVICE_B, t, b"beta", hop_count=3, trust_score=0.3)
        e2 = RouteEntry(DEVICE_B, t, b"beta", hop_count=1, trust_score=0.9)
        table.add(e1)
        table.add(e2)
        # Only one route via this transport+addr should exist.
        assert len(table.all_routes(DEVICE_B)) == 1
        assert table.best(DEVICE_B).trust_score == 0.9

    def test_remove(self):
        table = RouteTable()
        t, _ = make_transport()
        table.add(RouteEntry(DEVICE_B, t, b"beta"))
        table.remove(DEVICE_B)
        assert table.best(DEVICE_B) is None

    def test_known_destinations(self):
        table = RouteTable()
        t, _ = make_transport()
        table.add(RouteEntry(DEVICE_B, t, b"beta"))
        table.add(RouteEntry(DEVICE_C, t, b"gamma"))
        dests = table.known_destinations()
        assert DEVICE_B in dests
        assert DEVICE_C in dests


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

class TestRouter:
    def test_add_and_get_direct_route(self):
        router = Router(DEVICE_A)
        t, _ = make_transport()
        router.add_direct_route(DEVICE_B, t, b"beta")
        entry = router.get_route(DEVICE_B)
        assert entry.device_id == DEVICE_B
        assert entry.hop_count == 1

    def test_get_route_unknown_raises(self):
        router = Router(DEVICE_A)
        with pytest.raises(RoutingError):
            router.get_route(DEVICE_C)

    def test_has_route(self):
        router = Router(DEVICE_A)
        t, _ = make_transport()
        assert not router.has_route(DEVICE_B)
        router.add_direct_route(DEVICE_B, t, b"beta")
        assert router.has_route(DEVICE_B)

    def test_forward_delivers_packet(self):
        router = Router(DEVICE_A)
        t_a, t_b = make_transport()
        router.add_direct_route(DEVICE_B, t_a, b"beta")

        raw = b"ZTLP" + b"\x00" * 100  # dummy raw packet
        router.forward(raw, DEVICE_B)
        _, received = t_b.recv(timeout=1.0)
        assert received == raw

    def test_forward_unknown_raises(self):
        router = Router(DEVICE_A)
        with pytest.raises(RoutingError):
            router.forward(b"\x00" * 164, DEVICE_C)

    def test_local_device_id_validation(self):
        with pytest.raises(ValueError):
            Router(b"\x00" * 31)

    def test_route_table_property(self):
        router = Router(DEVICE_A)
        assert isinstance(router.route_table, RouteTable)


# ---------------------------------------------------------------------------
# ROUTE_ANNOUNCE payload encoding / decoding
# ---------------------------------------------------------------------------

class TestRouteAnnounce:
    def test_build_and_process_announce(self):
        router_a = Router(DEVICE_A)
        router_b = Router(DEVICE_B)
        t_ab, t_ba = make_transport()

        # A advertises itself.
        payload = router_a.build_announce_payload()
        assert len(payload) % Router._ENTRY_SIZE == 0

        # B processes A's announcement.
        updated = router_b.process_announce_payload(payload, t_ba, b"alpha")
        assert any(e.device_id == DEVICE_A for e in updated)
        assert router_b.has_route(DEVICE_A)

    def test_announce_includes_known_routes(self):
        router_a = Router(DEVICE_A)
        t, _ = make_transport()
        router_a.add_direct_route(DEVICE_C, t, b"gamma")

        payload = router_a.build_announce_payload()
        # Should contain at least 2 entries: DEVICE_A itself + DEVICE_C.
        assert len(payload) >= 2 * Router._ENTRY_SIZE

    def test_process_announce_skips_self(self):
        router = Router(DEVICE_A)
        t, _ = make_transport()

        # Build a payload that includes router's own device ID.
        another = Router(DEVICE_A)  # same local_id
        payload = another.build_announce_payload()

        updated = router.process_announce_payload(payload, t, b"src")
        # Should not create a route to itself.
        assert all(e.device_id != DEVICE_A for e in updated)

    def test_process_announce_bad_payload_raises(self):
        router = Router(DEVICE_A)
        t, _ = make_transport()
        with pytest.raises(RoutingError):
            router.process_announce_payload(b"\x00" * 35, t, b"src")  # 35 is not multiple of 34

    def test_trust_decay_over_hops(self):
        router = Router(DEVICE_A)
        t, _ = make_transport()

        # Announce DEVICE_B at hop_count=0 (direct).
        import struct
        payload = struct.pack("!32sH", DEVICE_B, 0)
        updated = router.process_announce_payload(payload, t, b"src", sender_trust_score=1.0)
        assert len(updated) == 1
        # hop_count in the announcement is 0, +1 for the hop to sender = 1.
        entry = updated[0]
        assert entry.hop_count == 1
        assert entry.trust_score <= 1.0

    def test_extra_destinations_forwarded(self):
        router_a = Router(DEVICE_A)
        t, _ = make_transport()
        router_a.add_direct_route(DEVICE_C, t, b"gamma")

        extra = [(DEVICE_B, 1)]
        payload = router_a.build_announce_payload(extra_destinations=extra)

        router_b = Router(DEVICE_B)
        updated = router_b.process_announce_payload(payload, t, b"alpha")
        dest_ids = {e.device_id for e in updated}
        assert DEVICE_A in dest_ids
        assert DEVICE_C in dest_ids
