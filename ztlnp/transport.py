"""
ZTLNP transport abstraction.

The core protocol (packet format, crypto, handshake) is completely decoupled
from the physical medium.  A ``Transport`` provides two operations:

* ``send(dest_addr, data)`` — push bytes to a destination.
* ``recv()`` — pull the next ``(src_addr, data)`` tuple from the medium.

Concrete implementations
------------------------

InProcessTransport
    Two linked :class:`InProcessTransport` objects share an in-memory queue.
    Used by tests and simulations with zero network overhead.

UdpTransport
    Wraps a standard UDP socket.  Compatible with IPv4 and IPv6.

All implementations are thread-safe: ``recv()`` blocks until a datagram
arrives or the transport is closed, and ``send()`` is safe to call from any
thread.
"""

from __future__ import annotations

import queue
import socket
import threading
from abc import ABC, abstractmethod
from typing import Optional, Tuple


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class Transport(ABC):
    """
    Abstract transport interface for ZTLNP.

    ``src_addr`` / ``dest_addr`` are opaque byte strings whose meaning
    depends on the concrete transport (e.g. ``b"host:port"`` for UDP,
    ``b"device_id"`` for in-process simulation, a BLE handle, etc.).
    """

    @abstractmethod
    def send(self, dest_addr: bytes, data: bytes) -> None:
        """
        Transmit *data* to *dest_addr*.

        Parameters
        ----------
        dest_addr:
            Transport-specific destination address.
        data:
            Raw bytes to transmit.
        """

    @abstractmethod
    def recv(self, timeout: Optional[float] = None) -> Tuple[bytes, bytes]:
        """
        Receive the next datagram.

        Parameters
        ----------
        timeout:
            Maximum seconds to wait.  ``None`` means block indefinitely.

        Returns
        -------
        (src_addr, data)

        Raises
        ------
        TransportTimeout
            If *timeout* is set and no datagram arrived within that window.
        TransportClosed
            If the transport has been closed.
        """

    @abstractmethod
    def close(self) -> None:
        """Release underlying resources."""

    def __enter__(self) -> "Transport":
        return self

    def __exit__(self, *_) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TransportTimeout(Exception):
    """No datagram arrived within the requested timeout."""


class TransportClosed(Exception):
    """The transport has been closed."""


# ---------------------------------------------------------------------------
# In-process transport (for tests and simulations)
# ---------------------------------------------------------------------------

class InProcessTransport(Transport):
    """
    A pair of linked in-memory transports that communicate via a shared queue.

    Create two endpoints with :meth:`create_pair`; messages sent on one
    arrive on the other.

    Thread safety
    -------------
    All methods are thread-safe.  ``recv()`` blocks until a message is
    available or *timeout* seconds elapse.

    Example
    -------
    ::

        alice_t, bob_t = InProcessTransport.create_pair()

        alice_t.send(b"bob", b"hello")
        src, data = bob_t.recv()   # src == b"alice", data == b"hello"
    """

    def __init__(self, local_addr: bytes) -> None:
        self._local_addr = local_addr
        self._inbox: "queue.Queue[Tuple[bytes, bytes]]" = queue.Queue()
        self._closed = threading.Event()
        self._peer: Optional["InProcessTransport"] = None

    @classmethod
    def create_pair(
        cls,
        addr_a: bytes = b"alice",
        addr_b: bytes = b"bob",
    ) -> Tuple["InProcessTransport", "InProcessTransport"]:
        """
        Create a pair of linked in-process transports.

        Returns
        -------
        (transport_a, transport_b)
        """
        a = cls(addr_a)
        b = cls(addr_b)
        a._peer = b
        b._peer = a
        return a, b

    def send(self, dest_addr: bytes, data: bytes) -> None:
        if self._closed.is_set():
            raise TransportClosed("Transport is closed")
        if self._peer is None:
            raise RuntimeError("InProcessTransport has no peer; use create_pair()")
        if self._peer._closed.is_set():
            raise TransportClosed("Peer transport is closed")
        self._peer._inbox.put((self._local_addr, data))

    def recv(self, timeout: Optional[float] = None) -> Tuple[bytes, bytes]:
        if self._closed.is_set():
            raise TransportClosed("Transport is closed")
        try:
            return self._inbox.get(block=True, timeout=timeout)
        except queue.Empty:
            raise TransportTimeout("No datagram within timeout")

    def close(self) -> None:
        self._closed.set()

    @property
    def local_addr(self) -> bytes:
        """The address of this endpoint."""
        return self._local_addr


# ---------------------------------------------------------------------------
# UDP transport
# ---------------------------------------------------------------------------

class UdpTransport(Transport):
    """
    UDP-based transport wrapping a standard Python ``socket.socket``.

    Parameters
    ----------
    bind_addr:
        ``(host, port)`` to bind to.  Use ``("", 0)`` to let the OS pick an
        ephemeral port.
    max_datagram:
        Maximum datagram size in bytes (default 65 535).

    Example
    -------
    ::

        server = UdpTransport(("127.0.0.1", 9000))
        client = UdpTransport(("127.0.0.1", 0))

        client.send(b"127.0.0.1:9000", b"hello")
        src, data = server.recv()

        client.close()
        server.close()
    """

    _SEP = b":"

    def __init__(
        self,
        bind_addr: Tuple[str, int] = ("127.0.0.1", 0),
        max_datagram: int = 65_535,
    ) -> None:
        self._max_datagram = max_datagram
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(bind_addr)
        self._closed = False

    @property
    def local_addr(self) -> Tuple[str, int]:
        """The ``(host, port)`` this socket is bound to."""
        return self._sock.getsockname()

    @property
    def local_addr_bytes(self) -> bytes:
        """The local address encoded as ``b"host:port"``."""
        host, port = self._sock.getsockname()
        return f"{host}:{port}".encode()

    # ------------------------------------------------------------------
    # Transport interface
    # ------------------------------------------------------------------

    def send(self, dest_addr: bytes, data: bytes) -> None:
        """
        Send *data* to *dest_addr* (format: ``b"host:port"``).
        """
        if self._closed:
            raise TransportClosed("Transport is closed")
        host, port = _parse_udp_addr(dest_addr)
        self._sock.sendto(data, (host, port))

    def recv(self, timeout: Optional[float] = None) -> Tuple[bytes, bytes]:
        """
        Receive the next UDP datagram.

        Returns
        -------
        (src_addr_bytes, data)
            ``src_addr_bytes`` has the form ``b"host:port"``.
        """
        if self._closed:
            raise TransportClosed("Transport is closed")
        self._sock.settimeout(timeout)
        try:
            data, (host, port) = self._sock.recvfrom(self._max_datagram)
        except socket.timeout:
            raise TransportTimeout("No datagram within timeout")
        src_addr = f"{host}:{port}".encode()
        return src_addr, data

    def close(self) -> None:
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_udp_addr(addr: bytes) -> Tuple[str, int]:
    """Parse ``b"host:port"`` into ``(host, port)``."""
    text = addr.decode()
    host, _, port_str = text.rpartition(":")
    return host, int(port_str)
