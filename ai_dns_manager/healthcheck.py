"""Checks the local UDP AND TCP listeners, not external API availability."""
import argparse
from . import wire
from .server import HEALTH_NAME
from .transports import Upstream, exchange


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=5353)
    args = p.parse_args()
    packet = wire.make_query(HEALTH_NAME)
    upstream = Upstream.parse({'ip': args.host, 'port': args.port})
    for tcp in (False, True):
        response = exchange(packet, upstream, 2, tcp=tcp)
        if wire.header(response)[1] & 15:
            raise SystemExit('DNS listener healthcheck failed')
    print('UDP/TCP listeners ready (not an AI API test)')


if __name__ == '__main__':
    main()
