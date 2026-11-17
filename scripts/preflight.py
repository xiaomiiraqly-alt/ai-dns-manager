#!/usr/bin/env python3
"""Read-only deployment preflight for a private Docker/AWG host.

Does not require root, does not modify Docker, DNS, firewall or routes.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys


def command(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return {'ok': result.returncode == 0, 'output': (result.stdout or result.stderr).strip()[:200]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'ok': False, 'output': type(exc).__name__}


def check(port=5353):
    results = {}
    results['docker'] = command('docker', 'info', '--format', '{{.ServerVersion}}') if shutil.which('docker') else {'ok': False, 'output': 'Docker not installed'}
    results['python'] = {'ok': sys.version_info >= (3, 10), 'output': sys.version.split()[0]}
    results['manager_config'] = command(sys.executable, '-m', 'ai_dns_manager.manager', 'validate')
    results['router_config'] = command(sys.executable, '-m', 'ai_dns_manager.server', '--check-config')
    # Loopback-only listener: check both UDP and TCP, without touching active services.
    for proto, socktype in [('udp', socket.SOCK_DGRAM), ('tcp', socket.SOCK_STREAM)]:
        try:
            with socket.socket(socket.AF_INET, socktype) as sock:
                sock.bind(('127.0.0.1', port))
                results['loopback_' + proto] = {'ok': True, 'output': 'available'}
        except OSError as exc:
            results['loopback_' + proto] = {'ok': False, 'output': type(exc).__name__}
    results['awg_container'] = command('docker', 'inspect', '--format', '{{.State.Status}}', 'amnezia-awg2') if results['docker']['ok'] else {'ok': False, 'output': 'Docker unavailable'}
    return {'ready_for_local_pilot': all(v['ok'] for v in results.values()), 'checks': results,
            'limitations': ['No real API generation checked', 'No AWG client routing tested', 'No firewall changes performed']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port', type=int, default=5353)
    p.add_argument('--output', default='-')
    args = p.parse_args()
    if not 1024 <= args.port <= 65535:
        p.error('Choose a port between 1024 and 65535')
    report = check(args.port)
    payload = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output == '-':
        print(payload)
    else:
        Path(args.output).write_text(payload + '\n', encoding='utf-8')
    raise SystemExit(0 if report['ready_for_local_pilot'] else 1)


if __name__ == '__main__':
    main()
