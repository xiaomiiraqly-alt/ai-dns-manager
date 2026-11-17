"""Opt-in DNS forwarder. No firewall or host configuration changes."""
import argparse
import ipaddress
import json
import logging
import socket
import socketserver
import struct
import threading
import time
from pathlib import Path

LOG = logging.getLogger("ai-dns-manager")


def question_name(packet):
    if len(packet) < 17 or struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("Expected one DNS question")
    labels = []
    pos = 12
    for _ in range(128):
        if pos >= len(packet):
            raise ValueError("Truncated question")
        n = packet[pos]
        pos += 1
        if n == 0:
            break
        if n > 63 or pos + n > len(packet):
            raise ValueError("Invalid DNS label")
        labels.append(packet[pos:pos+n].decode("ascii").lower())
        pos += n
    else:
        raise ValueError("Question too long")
    if pos + 4 > len(packet):
        raise ValueError("Missing question type")
    return ".".join(labels), pos + 4


def servfail(packet):
    if len(packet) < 12:
        return b""
    flags = struct.unpack_from("!H", packet, 2)[0]
    return packet[:2] + struct.pack("!HHHHH", 0x8000 | (flags & 0x7900) | 0x0002, 0, 0, 0, 0)


def match_domain(domain, suffix):
    suffix = suffix.lower().rstrip(".")
    return domain == suffix or domain.endswith("." + suffix)


class ProviderPool:
    def __init__(self, config):
        self.timeout = float(config.get("timeout_seconds", 3))
        if not 0 < self.timeout <= 15:
            raise ValueError("timeout_seconds must be 0..15")
        self.cooldown = float(config.get("cooldown_seconds", 30))
        if not 1 <= self.cooldown <= 3600:
            raise ValueError("cooldown_seconds must be 1..3600")
        self.groups = {}
        for group, ips in config["groups"].items():
            if not ips:
                raise ValueError(f"No upstreams for {group}")
            self.groups[group] = [str(ipaddress.IPv4Address(ip)) for ip in ips]
        self.rules = []
        for rule in config.get("rules", []):
            if rule["group"] not in self.groups:
                raise ValueError("Unknown group: " + rule["group"])
            self.rules.append((rule["domain"].lower().rstrip("."), rule["group"]))
        self.default = config["default_group"]
        if self.default not in self.groups:
            raise ValueError("Unknown default group")
        self.failures = {}
        self.lock = threading.Lock()

    def group_for(self, domain):
        for suffix, group in sorted(self.rules, key=lambda x: len(x[0]), reverse=True):
            if match_domain(domain, suffix):
                return group
        return self.default

    def exchange(self, packet, group, tcp=False):
        servers = self.groups[group]
        with self.lock:
            now = time.monotonic()
            candidates = [ip for ip in servers if self.failures.get((group, ip), 0) <= now]
            if not candidates:
                candidates = [min(servers, key=lambda ip: self.failures.get((group, ip), 0))]
        for ip in candidates:
            try:
                if tcp:
                    with socket.create_connection((ip, 53), timeout=self.timeout) as s:
                        s.settimeout(self.timeout)
                        s.sendall(struct.pack("!H", len(packet)) + packet)
                        length = recv_exact(s, 2)
                        response = recv_exact(s, struct.unpack("!H", length)[0])
                else:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(self.timeout)
                        s.sendto(packet, (ip, 53))
                        response, addr = s.recvfrom(65535)
                        if addr[0] != ip:
                            raise ValueError("Unexpected upstream IP")
                if len(response) < 12 or response[:2] != packet[:2] or not (response[2] & 0x80):
                    raise ValueError("Invalid upstream DNS response")
                if response[3] & 0x0f == 2:
                    raise ValueError("Upstream SERVFAIL")
                with self.lock:
                    self.failures.pop((group, ip), None)
                return response
            except (OSError, ValueError) as exc:
                LOG.warning("upstream_failure group=%s server=%s error=%s", group, ip, exc)
                with self.lock:
                    self.failures[(group, ip)] = time.monotonic() + self.cooldown
        return servfail(packet)


def recv_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise OSError("Truncated TCP DNS response")
        out.extend(chunk)
    return bytes(out)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        try:
            domain, _ = question_name(packet)
            response = self.server.pool.exchange(packet, self.server.pool.group_for(domain))
        except ValueError:
            response = servfail(packet)
        if response:
            sock.sendto(response, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(self.server.pool.timeout + 1)
        try:
            length = struct.unpack("!H", recv_exact(self.request, 2))[0]
            if length > 4096:
                return
            packet = recv_exact(self.request, length)
            domain, _ = question_name(packet)
            response = self.server.pool.exchange(packet, self.server.pool.group_for(domain), tcp=True)
            if response:
                self.request.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, ValueError):
            return


class ThreadedUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description="Opt-in DNS forwarder (UDP/TCP)")
    parser.add_argument("--config", default="config/router.json")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5353)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Invalid port")
    pool = ProviderPool(json.loads(Path(args.config).read_text()))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    udp = ThreadedUDP((args.listen, args.port), UDPHandler)
    tcp = ThreadedTCP((args.listen, args.port), TCPHandler)
    udp.pool = tcp.pool = pool
    for server in (udp, tcp):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    LOG.info("listening address=%s port=%s", args.listen, args.port)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for server in (udp, tcp):
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
