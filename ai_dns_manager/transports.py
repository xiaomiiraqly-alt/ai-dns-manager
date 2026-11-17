"""UDP/TCP, RFC 8484 DoH POST, and authenticated DoT. No proxy env or redirects."""
from dataclasses import dataclass
import http.client
import ipaddress
import socket
import ssl
import struct
import time
from urllib.parse import urlsplit
from .wire import MAX_WIRE, header, validate_response


@dataclass(frozen=True)
class Upstream:
    name: str
    protocol: str
    ip: str
    port: int = 53
    hostname: str = ''
    path: str = '/dns-query'

    @classmethod
    def parse(cls, value):
        if isinstance(value, str):
            value = {'name': value, 'ip': value, 'protocol': 'udp'}
        protocol = value.get('protocol', 'udp')
        if protocol not in ('udp', 'tcp', 'doh', 'dot'):
            raise ValueError('Unsupported protocol: ' + protocol)
        ip = str(ipaddress.ip_address(value.get('bootstrap_ip') or value.get('ip', '')))
        name = value.get('name', ip)
        if not isinstance(name, str) or not name or len(name) > 100 or any(ord(c) < 32 for c in name):
            raise ValueError('Invalid upstream name')
        hostname, path = value.get('hostname', ''), '/dns-query'
        port = value.get('port', {'udp': 53, 'tcp': 53, 'doh': 443, 'dot': 853}[protocol])
        if protocol == 'doh':
            parsed = urlsplit(value.get('url', ''))
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
                raise ValueError('DoH requires an HTTPS URL without credentials, query, or fragment')
            hostname, path, port = parsed.hostname, parsed.path or '/dns-query', parsed.port or 443
        if protocol in ('doh', 'dot'):
            if not hostname or len(hostname) > 253 or any(ord(c) <= 32 for c in hostname + path):
                raise ValueError('Encrypted DNS requires a certificate hostname')
            hostname = hostname.encode('idna').decode('ascii')
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('Invalid upstream port')
        return cls(name, protocol, ip, port, hostname, path)


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('DNS exchange deadline exceeded')
    return value


def recv_exact(sock, size, deadline=None):
    chunks = bytearray()
    while len(chunks) < size:
        if deadline is not None:
            sock.settimeout(remaining(deadline))
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise OSError('Truncated DNS TCP response')
        chunks.extend(chunk)
    return bytes(chunks)


class PinnedHTTPS(http.client.HTTPSConnection):
    """Connect to configured bootstrap IP, verify SNI/certificate against hostname."""
    def __init__(self, host, ip, port, timeout, context=None):
        super().__init__(host, port, timeout=timeout, context=context or ssl.create_default_context())
        self.bootstrap_ip = ip

    def connect(self):
        raw = socket.create_connection((self.bootstrap_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def exchange(packet, upstream, timeout=3, tcp=False, context=None):
    deadline = time.monotonic() + timeout
    protocol = 'tcp' if tcp and upstream.protocol == 'udp' else upstream.protocol
    if protocol == 'udp':
        family = socket.AF_INET6 if ':' in upstream.ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(remaining(deadline))
            sock.sendto(packet, (upstream.ip, upstream.port))
            while True:
                sock.settimeout(remaining(deadline))
                answer, sender = sock.recvfrom(MAX_WIRE)
                if sender[0] == upstream.ip and sender[1] == upstream.port:
                    validate_response(packet, answer)
                    break
        if header(answer)[1] & 0x0200:
            return exchange(packet, upstream, remaining(deadline), tcp=True, context=context)
    elif protocol in ('tcp', 'dot'):
        with socket.create_connection((upstream.ip, upstream.port), remaining(deadline)) as raw:
            raw.settimeout(remaining(deadline))
            if protocol == 'dot':
                conn = (context or ssl.create_default_context()).wrap_socket(raw, server_hostname=upstream.hostname)
            else:
                conn = raw
            try:
                conn.settimeout(remaining(deadline))
                conn.sendall(struct.pack('!H', len(packet)) + packet)
                size = struct.unpack('!H', recv_exact(conn, 2, deadline))[0]
                if size < 12:
                    raise ValueError('Invalid framed DNS length')
                answer = recv_exact(conn, size, deadline)
            finally:
                if conn is not raw:
                    conn.close()
    else:
        conn = PinnedHTTPS(upstream.hostname, upstream.ip, upstream.port, remaining(deadline), context)
        try:
            conn.request('POST', upstream.path, body=packet, headers={
                'Accept': 'application/dns-message', 'Content-Type': 'application/dns-message',
                'User-Agent': 'ai-dns-manager/0.3', 'Connection': 'close'})
            if conn.sock:
                conn.sock.settimeout(remaining(deadline))
            stream_socket = conn.sock
            response = conn.getresponse()
            if response.status != 200:
                raise ValueError('DoH HTTP ' + str(response.status))
            if response.getheader('Content-Type', '').split(';')[0].strip().lower() != 'application/dns-message':
                raise ValueError('DoH response is not application/dns-message')
            body = bytearray()
            while len(body) <= MAX_WIRE and not response.isclosed():
                stream_socket.settimeout(remaining(deadline))
                chunk = response.read1(min(8192, MAX_WIRE + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            answer = bytes(body)
            if len(answer) > MAX_WIRE:
                raise ValueError('Oversized DoH response')
        except http.client.HTTPException as exc:
            raise OSError('Malformed DoH HTTP response') from exc
        finally:
            conn.close()
    validate_response(packet, answer)
    if header(answer)[1] & 0x0200:
        raise ValueError('Truncated response on reliable DNS transport')
    return answer
