"""Domain policy, sticky failover, bounded cooldown and background DNS recovery."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import ipaddress
import json
import logging
import math
import secrets
import threading
import time
from . import transports, wire

LOG = logging.getLogger('ai-dns-manager')


def event(kind, **fields):
    LOG.info(json.dumps({'event': kind, **fields}, ensure_ascii=True, sort_keys=True))


def bounded(config, key, default, low, high):
    value = config.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError(f'{key} must be between {low} and {high}')
    return value


def match_domain(domain, suffix):
    domain, suffix = domain.lower().rstrip('.'), suffix.lower().rstrip('.')
    return domain == suffix or domain.endswith('.' + suffix)


@dataclass
class Health:
    failures: int = 0
    successes: int = 0
    until: float = 0
    reason: str = ''
    latency_ms: float = 0


class ProviderPool:
    def __init__(self, config, clock=time.monotonic, exchanger=transports.exchange):
        self.clock, self.exchanger = clock, exchanger
        self.timeout = bounded(config, 'timeout_seconds', 3, .05, 15)
        self.request_timeout = bounded(config, 'request_timeout_seconds', 8, .1, 60)
        self.cooldown = bounded(config, 'cooldown_seconds', 30, 1, 3600)
        self.failure_threshold = int(bounded(config, 'failure_threshold', 2, 1, 20))
        self.recovery_threshold = int(bounded(config, 'recovery_threshold', 2, 1, 20))
        self.health_interval = bounded(config, 'health_interval_seconds', 30, 0, 3600)
        self.probe_name = config.get('probe_name', 'example.com')
        wire.make_query(self.probe_name)
        self.groups, self.rules = {}, []
        groups = config.get('groups', {})
        if not isinstance(groups, dict) or not 1 <= len(groups) <= 32:
            raise ValueError('Expected 1..32 upstream groups')
        for name, items in groups.items():
            if not isinstance(name, str) or not name.isascii() or not name.replace('-', '').replace('_', '').isalnum():
                raise ValueError('Invalid group name')
            if not isinstance(items, list) or not 1 <= len(items) <= 8:
                raise ValueError('Expected 1..8 upstreams per group')
            self.groups[name] = [transports.Upstream.parse(item) for item in items]
            if len({up.name for up in self.groups[name]}) != len(items):
                raise ValueError('Duplicate upstream name within group')
        self.default = config.get('default_group')
        if self.default not in self.groups:
            raise ValueError('Unknown default group')
        for rule in config.get('rules', []):
            domain = rule['domain'].lower().rstrip('.')
            if not domain or '*' in domain:
                raise ValueError('Use a DNS suffix, not a wildcard')
            wire.make_query(domain)
            if rule['group'] not in self.groups:
                raise ValueError('Unknown rule group')
            self.rules.append((domain, rule['group']))
        if len({domain for domain, _ in self.rules}) != len(self.rules):
            raise ValueError('Duplicate domain rule')
        self.rules.sort(key=lambda item: len(item[0]), reverse=True)
        self.networks = [ipaddress.ip_network(net) for net in config.get('allowed_clients', ['127.0.0.0/8', '::1/128'])]
        self.max_workers = int(bounded(config, 'max_workers', 32, 1, 256))
        self.slots = threading.BoundedSemaphore(self.max_workers)
        self.lock = threading.RLock()
        self.active = {group: items[0].name for group, items in self.groups.items()}
        self.health = {(group, item.name): Health() for group, items in self.groups.items() for item in items}

    def allowed(self, address):
        try:
            ip = ipaddress.ip_address(address)
            return any(ip in net for net in self.networks)
        except ValueError:
            return False

    def group_for(self, domain):
        for suffix, group in self.rules:
            if match_domain(domain, suffix):
                return group
        return self.default

    def _failure(self, group, name, reason):
        with self.lock:
            state = self.health[group, name]
            state.failures += 1
            state.successes = 0
            state.reason = reason
            if state.failures >= self.failure_threshold:
                state.until = self.clock() + self.cooldown
            count = state.failures
        if count <= self.failure_threshold or count % 10 == 0:
            event('upstream_failure', group=group, upstream=name, reason=reason, failures=count)

    def _success(self, group, name, latency, probe=False):
        with self.lock:
            state = self.health[group, name]
            state.latency_ms = round(latency * 1000, 1)
            state.successes += 1
            was_down = bool(state.until)
            if not probe or state.successes >= self.recovery_threshold:
                state.failures, state.until, state.reason = 0, 0, ''
                if was_down:
                    event('upstream_recovered', group=group, upstream=name)
            if not probe and self.active[group] != name:
                previous = self.active[group]
                self.active[group] = name
                event('upstream_switch', group=group, previous=previous, active=name)

    def exchange(self, packet, group, tcp=False):
        wire.validate_query(packet)
        deadline = self.clock() + self.request_timeout
        # Do not preserve a predictable client transaction ID upstream.
        outgoing = secrets.token_bytes(2) + packet[2:]
        with self.lock:
            available = [up for up in self.groups[group] if self.health[group, up.name].until <= self.clock()]
            available.sort(key=lambda up: up.name != self.active[group])
        for upstream in available:
            timeout = min(self.timeout, deadline - self.clock())
            if timeout <= 0:
                break
            start = self.clock()
            try:
                answer = self.exchanger(outgoing, upstream, timeout, tcp=tcp)
                rcode = wire.validate_response(outgoing, answer)
                if rcode not in (0, 3):
                    raise ValueError('upstream_rcode_' + str(rcode))
                self._success(group, upstream.name, self.clock() - start)
                return packet[:2] + answer[2:]
            except (OSError, ValueError) as exc:
                # Never log query names, packet data, API keys or URL query strings.
                reason = str(exc) if str(exc).startswith('upstream_rcode_') else type(exc).__name__
                self._failure(group, upstream.name, reason)
        return wire.reply(packet)

    def _probe(self, group, upstream):
        start = self.clock()
        packet = wire.make_query(self.probe_name)
        try:
            answer = self.exchanger(packet, upstream, self.timeout)
            rcode = wire.validate_response(packet, answer)
            if rcode != 0 or not wire.a_records(answer):
                raise ValueError('Health probe returned no A records')
            self._success(group, upstream.name, self.clock() - start, probe=True)
        except (OSError, ValueError) as exc:
            self._failure(group, upstream.name, type(exc).__name__)

    def probe_once(self):
        # Probe active and eligible failed routes, but do not preempt a healthy active route.
        with self.lock:
            targets = [(group, up) for group, items in self.groups.items() for up in items
                       if self.health[group, up.name].until <= self.clock()]
        with ThreadPoolExecutor(max_workers=4) as workers:
            list(workers.map(lambda item: self._probe(*item), targets))

    def monitor(self, stop):
        if not self.health_interval:
            return
        while not stop.wait(self.health_interval):
            self.probe_once()
            event('health_summary', groups=self.snapshot())

    def snapshot(self):
        with self.lock:
            return {group: {'active': self.active[group], 'upstreams': [
                {'name': up.name, 'protocol': up.protocol,
                 'failures': self.health[group, up.name].failures,
                 'cooldown_remaining': round(max(0, self.health[group, up.name].until - self.clock()), 1),
                 'last_error': self.health[group, up.name].reason,
                 'latency_ms': self.health[group, up.name].latency_ms}
                for up in items]} for group, items in self.groups.items()}
