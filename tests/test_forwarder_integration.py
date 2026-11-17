"""Loopback-only integration test with a synthetic upstream; no Internet needed."""
import socket
import socketserver
import struct
import threading
import unittest
from ai_dns_manager.server import ProviderPool, ThreadedUDP, UDPHandler


class FakeUpstream(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        # Valid response with the original question and an A answer.
        response = packet[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0) + packet[12:] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("203.0.113.7")
        sock.sendto(response, self.client_address)


class IntegrationTests(unittest.TestCase):
    def test_udp_forwarder(self):
        # ProviderPool supports upstream port 53 only. Patch socket.socket to redirect
        # the upstream destination to the local test server.
        from unittest.mock import patch
        with socketserver.UDPServer(("127.0.0.1", 0), FakeUpstream) as upstream:
            thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            thread.start()
            original_socket = socket.socket

            class RedirectSocket:
                def __init__(self, *args, **kwargs):
                    self.inner = original_socket(*args, **kwargs)
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    self.inner.close()
                def settimeout(self, value):
                    self.inner.settimeout(value)
                def sendto(self, packet, dest):
                    return self.inner.sendto(packet, upstream.server_address)
                def recvfrom(self, size):
                    data, addr = self.inner.recvfrom(size)
                    return data, ("127.0.0.1", addr[1])

            config = {"groups": {"default": ["127.0.0.1"]}, "default_group": "default", "timeout_seconds": 1}
            pool = ProviderPool(config)
            query = b"\x12\x34\x01\x00" + struct.pack("!HHHH", 1, 0, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01"
            with patch("ai_dns_manager.server.socket.socket", RedirectSocket):
                result = pool.exchange(query, "default")
            self.assertEqual(result[:2], query[:2])
            self.assertIn(socket.inet_aton("203.0.113.7"), result)
            upstream.shutdown()


if __name__ == "__main__":
    unittest.main()
