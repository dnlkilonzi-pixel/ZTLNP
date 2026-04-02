"""
Tests for the ZTLNP transport abstraction.
"""

import threading
import time
import pytest

from ztlnp.transport import (
    InProcessTransport,
    UdpTransport,
    TransportTimeout,
    TransportClosed,
)


# ---------------------------------------------------------------------------
# InProcessTransport
# ---------------------------------------------------------------------------

class TestInProcessTransport:
    def test_create_pair(self):
        a, b = InProcessTransport.create_pair()
        assert a.local_addr == b"alice"
        assert b.local_addr == b"bob"

    def test_send_recv(self):
        a, b = InProcessTransport.create_pair()
        a.send(b"bob", b"hello")
        src, data = b.recv()
        assert src == b"alice"
        assert data == b"hello"

    def test_bidirectional(self):
        a, b = InProcessTransport.create_pair()
        a.send(b"bob", b"ping")
        b.send(b"alice", b"pong")
        src1, d1 = b.recv()
        src2, d2 = a.recv()
        assert d1 == b"ping"
        assert d2 == b"pong"

    def test_multiple_messages_ordered(self):
        a, b = InProcessTransport.create_pair()
        for i in range(5):
            a.send(b"bob", bytes([i]))
        for i in range(5):
            _, data = b.recv()
            assert data == bytes([i])

    def test_timeout_raises(self):
        a, _ = InProcessTransport.create_pair()
        with pytest.raises(TransportTimeout):
            a.recv(timeout=0.05)

    def test_send_after_close_raises(self):
        a, b = InProcessTransport.create_pair()
        a.close()
        with pytest.raises(TransportClosed):
            a.send(b"bob", b"x")

    def test_recv_after_close_raises(self):
        a, _ = InProcessTransport.create_pair()
        a.close()
        with pytest.raises(TransportClosed):
            a.recv(timeout=0.05)

    def test_send_to_closed_peer_raises(self):
        a, b = InProcessTransport.create_pair()
        b.close()
        with pytest.raises(TransportClosed):
            a.send(b"bob", b"x")

    def test_context_manager(self):
        with InProcessTransport.create_pair()[0] as t:
            assert t.local_addr == b"alice"

    def test_no_peer_raises(self):
        t = InProcessTransport(b"standalone")
        with pytest.raises(RuntimeError):
            t.send(b"nobody", b"x")

    def test_thread_safe(self):
        """Multiple sender threads should not corrupt messages."""
        a, b = InProcessTransport.create_pair()
        received = []
        lock = threading.Lock()

        def sender(msg: bytes):
            a.send(b"bob", msg)

        threads = [threading.Thread(target=sender, args=(bytes([i]),)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for _ in range(20):
            _, data = b.recv(timeout=1.0)
            with lock:
                received.append(data)

        assert sorted(received) == sorted([bytes([i]) for i in range(20)])


# ---------------------------------------------------------------------------
# UdpTransport
# ---------------------------------------------------------------------------

class TestUdpTransport:
    def test_bind_and_local_addr(self):
        t = UdpTransport(("127.0.0.1", 0))
        host, port = t.local_addr
        assert host == "127.0.0.1"
        assert port > 0
        t.close()

    def test_send_recv(self):
        server = UdpTransport(("127.0.0.1", 0))
        client = UdpTransport(("127.0.0.1", 0))
        try:
            dest = server.local_addr_bytes
            client.send(dest, b"hello UDP")
            src, data = server.recv(timeout=2.0)
            assert data == b"hello UDP"
        finally:
            client.close()
            server.close()

    def test_bidirectional(self):
        a = UdpTransport(("127.0.0.1", 0))
        b = UdpTransport(("127.0.0.1", 0))
        try:
            a.send(b.local_addr_bytes, b"ping")
            src, data = b.recv(timeout=2.0)
            assert data == b"ping"

            b.send(src, b"pong")
            _, data2 = a.recv(timeout=2.0)
            assert data2 == b"pong"
        finally:
            a.close()
            b.close()

    def test_timeout_raises(self):
        t = UdpTransport(("127.0.0.1", 0))
        try:
            with pytest.raises(TransportTimeout):
                t.recv(timeout=0.05)
        finally:
            t.close()

    def test_send_after_close_raises(self):
        t = UdpTransport(("127.0.0.1", 0))
        dest = t.local_addr_bytes
        t.close()
        with pytest.raises(TransportClosed):
            t.send(dest, b"x")

    def test_recv_after_close_raises(self):
        t = UdpTransport(("127.0.0.1", 0))
        t.close()
        with pytest.raises(TransportClosed):
            t.recv(timeout=0.05)

    def test_local_addr_bytes_format(self):
        t = UdpTransport(("127.0.0.1", 0))
        try:
            addr_bytes = t.local_addr_bytes
            assert b":" in addr_bytes
            host, _, port = addr_bytes.decode().rpartition(":")
            assert int(port) > 0
        finally:
            t.close()
