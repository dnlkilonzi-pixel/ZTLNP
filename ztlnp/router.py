"""
ZTLNP routing layer — identity-based mesh networking.

Background
----------
Traditional routing uses IP addresses.  ZTLNP routes by **device identity**
(the 32-byte SHA-256 of an Ed25519 public key), which means:

* Devices retain the same address even when their IP changes.
* Routing decisions can incorporate trust scores, not just topology.
* Multi-hop forwarding is possible without any notion of IP.

Route entries
-------------
A :class:`RouteEntry` records how to reach a device:

* ``transport`` — the :class:`~ztlnp.transport.Transport` to use.
* ``next_hop_addr`` — the transport-level address of the next hop.
* ``hop_count`` — number of hops to the destination (1 = directly reachable).
* ``trust_score`` — float in [0.0, 1.0] reflecting how much we trust the
  path (derived from the trust levels of intermediate devices).
* ``latency_ms`` — measured or estimated round-trip latency.

Route selection
---------------
When multiple routes exist for a destination, the :class:`Router` selects the
best one using a weighted score::

    score = trust_score / (hop_count * max(latency_ms, 1))

Higher scores are preferred (high trust, low hops, low latency).

Route announcements
-------------------
Devices flood :class:`~ztlnp.packet.PacketType.ROUTE_ANNOUNCE` packets to
advertise which device IDs they can reach.  The payload is a variable-length
list of (device_id, hop_count) pairs.  Each device that forwards the
announcement increments the hop_count.

Mesh forwarding
---------------
When the :class:`Router` receives a DATA packet destined for a device it is
not itself, it looks up the best route and calls ``transport.send()`` to
forward the raw packet bytes.  The packet is *not* re-encrypted or
re-signed — zero-trust means the destination will verify the original
sender's Ed25519 signature regardless of the forwarding path.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ztlnp.exceptions import RoutingError
from ztlnp.transport import Transport


# ---------------------------------------------------------------------------
# Route entry
# ---------------------------------------------------------------------------

@dataclass
class RouteEntry:
    """
    A single route to a remote device.

    Parameters
    ----------
    device_id:
        32-byte identity of the destination device.
    transport:
        Transport to use for this route.
    next_hop_addr:
        Transport-level address of the next hop (e.g. ``b"10.0.0.2:9000"``).
    hop_count:
        Number of hops to the destination.  Direct neighbours have hop_count=1.
    trust_score:
        Float in [0.0, 1.0].  1.0 = VERIFIED or ENDORSED path; lower values
        indicate TOFU or multi-hop paths through less-trusted intermediaries.
    latency_ms:
        Measured or estimated one-way latency in milliseconds.
    last_seen:
        Unix timestamp of the last route advertisement for this entry.
    """

    device_id: bytes
    transport: Transport
    next_hop_addr: bytes
    hop_count: int = 1
    trust_score: float = 1.0
    latency_ms: float = 0.0
    last_seen: float = field(default_factory=time.time)

    @property
    def score(self) -> float:
        """Route quality score: higher is better."""
        return self.trust_score / (self.hop_count * max(self.latency_ms, 1.0))

    def __lt__(self, other: "RouteEntry") -> bool:
        return self.score < other.score


# ---------------------------------------------------------------------------
# Route table
# ---------------------------------------------------------------------------

class RouteTable:
    """
    Per-destination collection of :class:`RouteEntry` objects.

    Maintains a list of routes per destination and always returns the best
    (highest :attr:`RouteEntry.score`) one.

    Parameters
    ----------
    stale_after:
        Routes not refreshed within this many seconds are considered stale and
        will not be returned.  Defaults to 300 seconds (5 minutes).
    """

    def __init__(self, stale_after: float = 300.0) -> None:
        self._stale_after = stale_after
        self._routes: Dict[bytes, List[RouteEntry]] = {}

    def add(self, entry: RouteEntry) -> None:
        """
        Insert or update a route.

        If a route via the same transport to the same destination already
        exists it is replaced; otherwise the entry is appended.
        """
        entries = self._routes.setdefault(entry.device_id, [])
        for i, existing in enumerate(entries):
            if existing.transport is entry.transport and existing.next_hop_addr == entry.next_hop_addr:
                entries[i] = entry
                return
        entries.append(entry)

    def best(self, device_id: bytes) -> Optional[RouteEntry]:
        """
        Return the best non-stale route for *device_id*, or ``None``.
        """
        entries = self._routes.get(device_id, [])
        now = time.time()
        valid = [e for e in entries if (now - e.last_seen) <= self._stale_after]
        if not valid:
            return None
        return max(valid, key=lambda e: e.score)

    def all_routes(self, device_id: bytes) -> List[RouteEntry]:
        """Return all stored routes for *device_id* (including stale ones)."""
        return list(self._routes.get(device_id, []))

    def remove(self, device_id: bytes) -> None:
        """Remove all routes for *device_id*."""
        self._routes.pop(device_id, None)

    def known_destinations(self) -> List[bytes]:
        """Return all device IDs for which at least one route exists."""
        return list(self._routes.keys())


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

class Router:
    """
    Identity-based mesh router for ZTLNP.

    The :class:`Router` sits between a :class:`~ztlnp.device.Device` and one
    or more :class:`~ztlnp.transport.Transport` instances.  It:

    1. Maintains a :class:`RouteTable`.
    2. Forwards packets destined for remote devices it is not itself.
    3. Processes :class:`~ztlnp.packet.PacketType.ROUTE_ANNOUNCE` payloads
       to learn about new routes.
    4. Lets the device build ROUTE_ANNOUNCE payloads to advertise reachability.

    Parameters
    ----------
    local_device_id:
        32-byte identity of the local device.
    route_table:
        Optional existing :class:`RouteTable`.  A fresh one is created if not
        supplied.
    """

    # Format for a single route advertisement entry inside a ROUTE_ANNOUNCE
    # payload: [device_id (32 B)][hop_count (2 B, big-endian)]
    _ENTRY_FMT = "!32sH"
    _ENTRY_SIZE = struct.calcsize(_ENTRY_FMT)  # 34 bytes

    def __init__(
        self,
        local_device_id: bytes,
        route_table: Optional[RouteTable] = None,
    ) -> None:
        if len(local_device_id) != 32:
            raise ValueError("local_device_id must be 32 bytes")
        self._local_id = local_device_id
        self._table = route_table or RouteTable()

    # ------------------------------------------------------------------
    # Route management
    # ------------------------------------------------------------------

    def add_direct_route(
        self,
        device_id: bytes,
        transport: Transport,
        next_hop_addr: bytes,
        trust_score: float = 1.0,
        latency_ms: float = 0.0,
    ) -> RouteEntry:
        """
        Register a direct (one-hop) route to *device_id*.

        Parameters
        ----------
        device_id:
            32-byte identity of the destination.
        transport:
            Transport to use.
        next_hop_addr:
            Transport-level address of the destination.
        trust_score:
            Initial trust score in [0.0, 1.0].
        latency_ms:
            Estimated latency in milliseconds.

        Returns
        -------
        RouteEntry
            The newly created route entry.
        """
        entry = RouteEntry(
            device_id=device_id,
            transport=transport,
            next_hop_addr=next_hop_addr,
            hop_count=1,
            trust_score=trust_score,
            latency_ms=latency_ms,
        )
        self._table.add(entry)
        return entry

    def get_route(self, device_id: bytes) -> RouteEntry:
        """
        Return the best route for *device_id*.

        Raises
        ------
        RoutingError
            If no route is known for *device_id*.
        """
        entry = self._table.best(device_id)
        if entry is None:
            raise RoutingError(
                f"No route to device {device_id.hex()}"
            )
        return entry

    def has_route(self, device_id: bytes) -> bool:
        """Return ``True`` if a non-stale route to *device_id* is known."""
        return self._table.best(device_id) is not None

    # ------------------------------------------------------------------
    # Forwarding
    # ------------------------------------------------------------------

    def forward(self, raw_packet: bytes, dest_device_id: bytes) -> None:
        """
        Forward a raw packet to *dest_device_id* via the best known route.

        The packet is *not* modified — zero-trust means the final recipient
        verifies the original sender's signature.

        Parameters
        ----------
        raw_packet:
            Serialised packet bytes (as produced by ``Packet.to_bytes()``).
        dest_device_id:
            32-byte identity of the intended recipient.

        Raises
        ------
        RoutingError
            If no route to *dest_device_id* is known.
        """
        entry = self.get_route(dest_device_id)
        entry.transport.send(entry.next_hop_addr, raw_packet)

    # ------------------------------------------------------------------
    # ROUTE_ANNOUNCE payload encoding / decoding
    # ------------------------------------------------------------------

    def build_announce_payload(
        self,
        extra_destinations: Optional[List[Tuple[bytes, int]]] = None,
    ) -> bytes:
        """
        Build a ROUTE_ANNOUNCE payload advertising the local device and any
        additional destinations from the route table.

        Payload layout::

            [device_id(32)][hop_count(2)] × N entries

        Parameters
        ----------
        extra_destinations:
            Additional ``(device_id, hop_count)`` tuples to include (e.g.
            destinations learned from other peers).  Each hop_count is
            incremented by 1 to account for the extra hop through this device.

        Returns
        -------
        bytes
            Variable-length payload, always a multiple of 34 bytes.
        """
        entries: List[Tuple[bytes, int]] = [(self._local_id, 0)]

        if extra_destinations:
            for dev_id, hops in extra_destinations:
                if dev_id != self._local_id:
                    entries.append((dev_id, hops + 1))

        # Also advertise known direct routes.
        for dev_id in self._table.known_destinations():
            route = self._table.best(dev_id)
            if route is not None:
                entries.append((dev_id, route.hop_count + 1))

        # De-duplicate (keep lowest hop_count for each device_id).
        seen: Dict[bytes, int] = {}
        for dev_id, hops in entries:
            if dev_id not in seen or hops < seen[dev_id]:
                seen[dev_id] = hops

        payload = bytearray()
        for dev_id, hops in seen.items():
            payload += struct.pack(self._ENTRY_FMT, dev_id, min(hops, 0xFFFF))
        return bytes(payload)

    def process_announce_payload(
        self,
        payload: bytes,
        via_transport: Transport,
        via_addr: bytes,
        sender_trust_score: float = 1.0,
    ) -> List[RouteEntry]:
        """
        Parse a ROUTE_ANNOUNCE payload and update the route table.

        Parameters
        ----------
        payload:
            Raw bytes from a ROUTE_ANNOUNCE packet's payload.
        via_transport:
            Transport through which the announcement arrived.
        via_addr:
            Transport-level address of the announcing device.
        sender_trust_score:
            Trust score of the sender (used to compute path trust scores for
            multi-hop routes).

        Returns
        -------
        List[RouteEntry]
            All new or updated route entries that were added to the table.
        """
        if len(payload) % self._ENTRY_SIZE != 0:
            raise RoutingError(
                f"ROUTE_ANNOUNCE payload size {len(payload)} is not a multiple "
                f"of {self._ENTRY_SIZE}"
            )

        updated: List[RouteEntry] = []
        for offset in range(0, len(payload), self._ENTRY_SIZE):
            dev_id, hop_count = struct.unpack_from(self._ENTRY_FMT, payload, offset)
            if dev_id == self._local_id:
                continue  # Never create a route to ourselves.

            # Path trust decays slightly with each additional hop.
            path_trust = sender_trust_score * (0.9 ** hop_count)
            entry = RouteEntry(
                device_id=dev_id,
                transport=via_transport,
                next_hop_addr=via_addr,
                hop_count=hop_count + 1,  # +1 for the hop to the sender
                trust_score=min(path_trust, 1.0),
            )
            self._table.add(entry)
            updated.append(entry)

        return updated

    @property
    def local_device_id(self) -> bytes:
        """32-byte identity of the local device."""
        return self._local_id

    @property
    def route_table(self) -> RouteTable:
        """The underlying :class:`RouteTable`."""
        return self._table
