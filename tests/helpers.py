import socket
import socketserver
import struct
import threading
from contextlib import contextmanager
from ai_dns_manager import wire
from ai_dns_manager.transports import recv_exact


def answer(query, rcode=0, ip='203.0.113.7', truncated=False):
    end = wire.question(query)[3]
    flags = 0x8180 | rcode | (0x0200 if truncated else 0)
    count = int(not rcode and not truncated)
    result = query[:2] + struct.pack('!5H', flags, 1, count, 0, 0) + query[12:end]
    if count:
        result += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton(ip)
    return result


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        self.server.calls += 1
        sock.sendto(answer(data, truncated=self.server.truncated), self.client_address)


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            size = struct.unpack('!H', recv_exact(self.request, 2))[0]
            result = answer(recv_exact(self.request, size))
            self.server.calls += 1
            self.request.sendall(struct.pack('!H', len(result)) + result)
        except OSError:
            pass


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
