"""Opt-in private DNS listener. Never modifies host DNS, firewall, or VPN."""
import argparse
import ipaddress
import json
import logging
import signal
import socket
import socketserver
import struct
import threading
import time
from pathlib import Path
from . import wire
from .policy import ProviderPool, match_domain, event
from .transports import recv_exact

question_name = wire.question_name
servfail = wire.reply
HEALTH_NAME = 'health.ai-dns-manager.invalid'


def process(pool, packet, tcp=False):
    wire.validate_query(packet)
    name, _ = wire.question_name(packet)
    if name == HEALTH_NAME:
        return wire.reply(packet, 0)
    answer = pool.exchange(packet, pool.group_for(name), tcp=tcp)
    if not tcp and len(answer) > wire.udp_limit(packet):
        return wire.reply(packet, 0, truncated=True)
    return answer


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        try:
            response = process(self.server.pool, packet)
        except (ValueError, OSError):
            response = wire.reply(packet, 1)
        if response:
            try:
                sock.sendto(response, self.client_address)
            except OSError:
                pass


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Support several sequential queries per TCP connection, with a lifetime cap.
        deadline = time.monotonic() + 30
        for _ in range(16):
            try:
                self.request.settimeout(5)
                size = struct.unpack('!H', recv_exact(self.request, 2, min(deadline, time.monotonic() + 5)))[0]
                if not 12 <= size <= 4096:
                    return
                packet = recv_exact(self.request, size, min(deadline, time.monotonic() + 5))
                response = process(self.server.pool, packet, tcp=True)
                self.request.settimeout(5)
                if response:
                    self.request.sendall(struct.pack('!H', len(response)) + response)
            except (OSError, ValueError):
                return
            if time.monotonic() >= deadline:
                return


class BoundedMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True

    def verify_request(self, request, client_address):
        return self.pool.allowed(client_address[0])

    def process_request(self, request, client_address):
        if not self.pool.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.pool.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.pool.slots.release()


class ThreadedUDP(BoundedMixIn, socketserver.UDPServer):
    pass


class ThreadedTCP(BoundedMixIn, socketserver.TCPServer):
    request_queue_size = 32


def main():
    parser = argparse.ArgumentParser(description='Private DNS forwarder with UDP/TCP/DoH/DoT upstreams')
    parser.add_argument('--config', default='config/router.json')
    parser.add_argument('--listen', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5353)
    parser.add_argument('--check-config', action='store_true')
    args = parser.parse_args()
    try:
        ipaddress.IPv4Address(args.listen)  # IPv4 listener; upstreams may also be IPv6.
        if not 1 <= args.port <= 65535:
            raise ValueError('Invalid listener port')
        pool = ProviderPool(json.loads(Path(args.config).read_text()))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error('Configuration: ' + str(exc))
    if args.check_config:
        print('Configuration valid; no sockets opened')
        return
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    stop, servers = threading.Event(), []
    threads = []
    try:
        udp = ThreadedUDP((args.listen, args.port), UDPHandler)
        servers.append(udp)
        tcp = ThreadedTCP((args.listen, args.port), TCPHandler)
        servers.append(tcp)
        for server in servers:
            server.pool = pool
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
            thread.start()
            threads.append(thread)
        monitor = threading.Thread(target=pool.monitor, args=(stop,), daemon=True)
        monitor.start()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        event('listening', address=args.listen, port=args.port, groups=list(pool.groups))
        stop.wait()
    finally:
        stop.set()
        for server, _ in zip(servers, threads):
            server.shutdown()
        for server in servers:
            server.server_close()
        event('stopped')


if __name__ == '__main__':
    main()
