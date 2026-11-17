import socket
import struct
import unittest
from unittest.mock import patch
from ai_dns_manager.__main__ import dns_query


class FakeSocket:
    def __init__(self, *args, **kwargs):
        self.packet = None
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def settimeout(self, timeout):
        pass
    def sendto(self, packet, dest):
        self.packet = packet
        self.dest = dest
    def recvfrom(self, size):
        qid = struct.unpack_from("!H", self.packet)[0]
        question = self.packet[12:]
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("203.0.113.7")
        return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer, (self.dest[0], 53)


class DNSPacketTests(unittest.TestCase):
    @patch("socket.socket", FakeSocket)
    def test_a_record_response(self):
        self.assertEqual(dns_query("example.com", "192.0.2.53", 1), ["203.0.113.7"])

    def test_invalid_label(self):
        with self.assertRaises(ValueError):
            dns_query("x"*64 + ".com", "127.0.0.1", 1)


if __name__ == "__main__":
    unittest.main()
