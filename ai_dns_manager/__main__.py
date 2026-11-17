"""Batch provider diagnostics. DNS settings are never changed by this command."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import time
from . import wire
from .transports import Upstream, exchange


def dns_query(name, server, timeout):
    query = wire.make_query(name)
    result = exchange(query, Upstream.parse(server), timeout)
    return wire.a_records(result)


def check_tls(host, ip, timeout):
    started = time.monotonic()
    if not ipaddress.ip_address(ip).is_global:
        return {'ok': False, 'error': 'Non-public address; TLS probe skipped'}
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as conn:
                return {'ok': True, 'latency_ms': round((time.monotonic() - started)*1000),
                        'tls_version': conn.version(), 'remote_ip': conn.getpeername()[0]}
    except (OSError, ValueError) as exc:
        return {'ok': False, 'error': type(exc).__name__}


def diagnostic(host, upstream, timeout):
    item = {'name': upstream.name, 'protocol': upstream.protocol, 'tls': [], 'api': {'category': 'NOT_TESTED'}}
    start = time.monotonic()
    try:
        query = wire.make_query(host)
        answer = exchange(query, upstream, timeout)
        addresses = wire.a_records(answer)
        rcode = wire.header(answer)[1] & 15
        item['dns'] = {'ok': rcode == 0 and bool(addresses), 'rcode': rcode, 'addresses': addresses,
                       'latency_ms': round((time.monotonic() - start)*1000)}
        item['tls'] = [{'ip': ip, **check_tls(host, ip, timeout)} for ip in addresses[:2]]
    except (OSError, ValueError) as exc:
        item['dns'] = {'ok': False, 'error': type(exc).__name__}
    return item


def main():
    p = argparse.ArgumentParser(description='Read-only batch DNS/TLS checks (UDP/TCP/DoH/DoT)')
    p.add_argument('--config', default='config/providers.json')
    p.add_argument('--output', default='diagnostics.json', help="JSON report path, or '-' for stdout")
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--gemini', action='store_true', help='Opt-in: send a small authenticated Gemini generation request; may incur charges')
    p.add_argument('--max-api-probes', type=int, default=2)
    args = p.parse_args()
    try:
        cfg = json.loads(Path(args.config).read_text())
        host, timeout = cfg['target'], float(cfg.get('timeout_seconds', 4))
        wire.make_query(host)
        if not .1 <= timeout <= 30 or not 1 <= args.workers <= 8 or not 1 <= args.max_api_probes <= 8:
            raise ValueError('Invalid timeout, workers, or API probe limit')
        upstreams = [Upstream.parse(item) for item in cfg['providers'] if item.get('enabled', True)]
        if not 1 <= len(upstreams) <= 64:
            raise ValueError('Expected 1..64 providers')
        if args.gemini:
            key = os.getenv('GEMINI_API_KEY') or os.getenv('OPENAI_API_KEY')
            model = os.getenv('GEMINI_MODEL') or os.getenv('INFERENCE_TEXT_MODEL')
            if host != 'generativelanguage.googleapis.com' or not key or not model:
                raise ValueError('Gemini probe requires the Google API hostname, GEMINI_API_KEY and GEMINI_MODEL (or OPENAI_API_KEY and INFERENCE_TEXT_MODEL)')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        p.error(str(exc))
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda up: diagnostic(host, up, timeout), upstreams))
    if args.gemini:
        from .gemini import probe
        tested = {}
        for result in results:
            for tls in result['tls']:
                ip = tls['ip']
                if not tls['ok']:
                    continue
                if ip not in tested and len(tested) < args.max_api_probes:
                    tested[ip] = probe(ip, key, model)
                if ip in tested:
                    result['api'] = {**tested[ip], 'remote_ip': ip}
                break
    report = {'timestamp': datetime.now(timezone.utc).isoformat(), 'target': host, 'results': results,
              'note': 'DNS and TLS success do not prove AI API usability. API generation is opt-in.'}
    if args.output == '-':
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        # Atomic replacement; do not leave partial reports if a process is interrupted.
        import tempfile
        destination = Path(args.output)
        fd, temporary = tempfile.mkstemp(prefix='.ai-dns-', dir=destination.resolve().parent)
        try:
            with os.fdopen(fd, 'w') as out:
                json.dump(report, out, indent=2, ensure_ascii=False)
                out.write('\n')
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        for result in results:
            print(result['name'] + ': DNS=' + str(result['dns']['ok']) +
                  ' TLS_OK=' + str(sum(t['ok'] for t in result['tls'])) + ' API=' + result['api']['category'])
        print('Saved:', args.output)


if __name__ == '__main__':
    main()
