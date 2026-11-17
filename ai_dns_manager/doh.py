"""RFC 8484 DNS-message helper; JSON-only DNS is deliberately not used for forwarding."""
from . import wire
from .transports import Upstream, exchange


def doh_query(host, endpoint, timeout, bootstrap_ip):
    upstream = Upstream.parse({'protocol': 'doh', 'url': endpoint, 'bootstrap_ip': bootstrap_ip})
    return wire.a_records(exchange(wire.make_query(host), upstream, timeout))
