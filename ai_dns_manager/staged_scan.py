"""Budgeted DNS-first AI scan.

Probe all candidate DNS transports cheaply; deeply inspect only a rotating,
diverse frontier. The selected route still needs complete per-answer HTTP
evidence. Nothing in this module modifies host DNS or the VPN.
"""
from concurrent.futures import ThreadPoolExecutor
import time

from . import wire
from .catalogue import public_ip
from .service_scan import scan
from .transports import Upstream, exchange


def _safe_progress(callback, phase, **fields):
    if callback is not None:
        callback({'phase': phase, 'timestamp': time.time(), **fields})


def _frontier(rows, maximum, cycle=0, previous=(), priority_provider_ids=()):
    """Prefer non-reference answers and distinct reply sets; rotate unvisited sets."""
    if not rows or maximum <= 0:
        return []
    reference_sets = {tuple(r['addresses']) for r in rows if r['candidate']['provider_id'] == 'reference'}
    groups = {}
    for row in rows:
        groups.setdefault(tuple(row['addresses']), []).append(row)
    for members in groups.values():
        members.sort(key=lambda r: (r['latency_ms'], r['candidate']['id']))
    different = sorted((key for key in groups if key not in reference_sets),
                       key=lambda key: min(r['latency_ms'] for r in groups[key]))
    common = sorted((key for key in groups if key in reference_sets),
                    key=lambda key: min(r['latency_ms'] for r in groups[key]))
    # Rotate only the distinct sets; keep a reference for a stable baseline.
    if different:
        offset = (cycle * maximum) % len(different)
        different = different[offset:] + different[:offset]
    selected, seen = [], set()
    def take(row):
        c = row['candidate']
        if c['id'] not in seen and len(selected) < maximum:
            selected.append(c)
            seen.add(c['id'])
    byid = {r['candidate']['id']: r for r in rows}
    # A long historical plan may contain dozens of distinct preferred
    # routes. It must not consume the entire small mandatory scan frontier.
    previous_limit=max(1,maximum//4)
    for candidate_id in previous:
        if len(selected)>=previous_limit:
            break
        if candidate_id in byid:
            take(byid[candidate_id])
    # Mandatory generation cannot be verified if its trusted providers are
    # crowded out by many merely reachable/old candidates. Reserve a small
    # number of diverse DNS-answer groups for explicit credential allowlists.
    # Never treat trust/priority as proof: the full HTTPS generation probe is
    # still required before a route is eligible.
    for provider_id in priority_provider_ids:
        alternatives=sorted((r for r in rows if r['candidate']['provider_id']==provider_id),
                            key=lambda r:(r['latency_ms'],r['candidate']['id']))
        provider_answers=set()
        for row in alternatives:
            signature=tuple(row['addresses'])
            if signature in provider_answers:
                continue
            provider_answers.add(signature)
            take(row)
            if len(provider_answers)>=3 or len(selected)>=maximum:
                break
    # A fresh baseline is valuable even if all smart DNS candidates are down.
    for key in common[:1]:
        reference = [r for r in groups[key] if r['candidate']['provider_id'] == 'reference']
        if reference:
            take(reference[0])
    for key in different + common:
        if len(selected) >= maximum:
            break
        take(groups[key][0])
    # Add backups with different provider identities when space remains.
    for key in different + common:
        if len(selected) >= maximum:
            break
        for row in groups[key]:
            if row['candidate']['id'] in seen:
                continue
            if not any(byid[c['id']]['candidate']['provider_id'] == row['candidate']['provider_id'] for c in selected):
                take(row)
                break
    for key in different + common:
        for row in groups[key]:
            if len(selected) >= maximum:
                break
            take(row)
    return selected


def staged_scan(candidates, services, *, workers=8, round_budget=300,
                authorized=(), max_api_requests=8, credential_providers=('reference',),
                preferred_endpoints=(), stop=None, progress=None, cycle=0,
                required_candidates=12, preferred_candidates=4,
                dns_timeout=1.5, http_timeout=2.5,
                required_seconds=55, preferred_seconds=75,
                dns_exchange=exchange, scanner=scan, clock=time.monotonic):
    """Stage 1 DNS prefilter → Stage 2 required HTTP → Stage 3 preferred HTTP.

    An untested route is never eligible. Unchecked optional services are marked
    unscanned, not failed. Only the scanner can declare HTTP/API evidence.
    """
    if not (1 <= workers <= 16 and 1 <= required_candidates <= 32
            and 1 <= preferred_candidates <= 16 and .1 <= dns_timeout <= 8
            and .1 <= http_timeout <= 10 and 1 <= required_seconds <= 900
            and 1 <= preferred_seconds <= 900 and 1 <= round_budget <= 1800):
        raise ValueError('Invalid staged scan limits')
    active = [s for s in services if s['mode'] != 'off']
    required = [s for s in active if s['mode'] == 'required']
    preferred = [s for s in active if s['mode'] == 'preferred']
    target = (required or preferred)
    start = clock()
    deadline = start + round_budget
    _safe_progress(progress, 'dns_prefilter', candidates=len(candidates),
                   required=len(required), preferred=len(preferred),
                   scanned=0, eligible=0)
    if not target or not candidates:
        return {'checked_at': time.time(), 'results': [], 'services': [
            {'id': s['id'], 'mode': s['mode'], 'minimum_evidence': s['minimum_evidence']} for s in services],
            'api_requests': 0, 'unscanned_services': [s['id'] for s in active],
            'phase_stats': {'candidates': len(candidates), 'dns_live': 0,
                            'required_tested': 0, 'preferred_tested': 0},
            'note': 'No active services or candidate DNS endpoints.'}
    # A single mandatory hostname is the fast discriminator; other required
    # hostnames still undergo a full DNS/HTTPS test on the selected frontier.
    probe_domain = target[0]['domain']
    packet = wire.make_query(probe_domain)
    def probe(candidate):
        if (stop and stop.is_set()) or clock() >= deadline:
            return None
        began = clock()
        try:
            answer = dns_exchange(packet, Upstream.parse(candidate['upstream']),
                                  min(dns_timeout, max(.01, deadline-clock())))
            if wire.header(answer)[1] & 15:
                return None
            addresses = tuple(public_ip(ip) for ip in wire.a_records(answer))
            if not addresses or len(addresses) > 16:
                return None
            return {'candidate': candidate, 'addresses': addresses,
                    'latency_ms': round((clock()-began)*1000, 1)}
        except (OSError, ValueError):
            return None
    with ThreadPoolExecutor(max_workers=min(workers, 8)) as executor:
        checked = list(executor.map(probe, candidates))
    responsive = [r for r in checked if r is not None]
    previous_ids = [c for c, sid in preferred_endpoints if sid in {s['id'] for s in required}]
    frontier = _frontier(responsive, required_candidates, cycle, previous_ids,
                         priority_provider_ids=[p for p in credential_providers if p!='reference'] if authorized else ())
    _safe_progress(progress, 'required_services', candidates=len(candidates),
                   dns_live=len(responsive), selected=len(frontier),
                   required=len(required), preferred=len(preferred))
    reports = []
    remaining_api = max_api_requests
    required_tested = 0
    if required and frontier and deadline-clock() >= 1 and not (stop and stop.is_set()):
        seconds = min(required_seconds, deadline-clock())
        req_report = scanner(frontier, required, workers=min(workers, 8), timeout=http_timeout,
                             round_budget=seconds, authorized=authorized,
                             max_api_requests=remaining_api,
                             credential_providers=credential_providers,
                             preferred_endpoints=preferred_endpoints, stop=stop)
        reports.extend(req_report['results'])
        remaining_api = max(0, remaining_api-req_report.get('api_requests', 0))
        required_tested = len(frontier)*len(required)
    tested_required = {r['service'] for r in reports if r.get('eligible')}
    all_required = all(s['id'] in tested_required for s in required)
    _safe_progress(progress, 'preferred_services', required_ok=all_required,
                   required_tested=required_tested,
                   required_missing=[s['id'] for s in required if s['id'] not in tested_required],
                   http_evaluations=len(reports))
    preferred_tested = 0
    if preferred and responsive and deadline-clock() >= 1 and not (stop and stop.is_set()):
        winner_ids = {r['candidate'] for r in reports if r.get('eligible') and
                      r['service'] in {s['id'] for s in required}}
        # Keep each required winner and recent healthy routes when possible.
        winners = [c for c in frontier if c['id'] in winner_ids]
        prior = [c for c in frontier if c['id'] in previous_ids]
        addition = _frontier(responsive, preferred_candidates, cycle, previous_ids)
        chosen, ids = [], set()
        for c in winners + prior + addition:
            if c['id'] not in ids and len(chosen) < preferred_candidates:
                ids.add(c['id']);chosen.append(c)
        seconds = min(preferred_seconds if all_required else 12,
                      deadline-clock())
        pref_report = scanner(chosen, preferred, workers=min(workers, 8),
                              timeout=http_timeout, round_budget=seconds,
                              authorized=authorized, max_api_requests=remaining_api,
                              credential_providers=credential_providers,
                              preferred_endpoints=preferred_endpoints, stop=stop)
        reports.extend(pref_report['results'])
        remaining_api = max(0, remaining_api-pref_report.get('api_requests', 0))
        preferred_tested = len(chosen)*len(preferred)
    scanned_ids = {r['service'] for r in reports}
    unscanned = [s['id'] for s in active if s['id'] not in scanned_ids]
    summary = {'candidates': len(candidates), 'dns_live': len(responsive),
               'required_tested': required_tested, 'required_ok': all_required,
               'required_missing': [s['id'] for s in required if s['id'] not in tested_required],
               'preferred_tested': preferred_tested,
               'total_evaluations': len(reports),
               'elapsed_seconds': round(clock()-start, 2),
               'unscanned': len(unscanned)}
    _safe_progress(progress, 'complete', **summary)
    return {'checked_at': time.time(), 'results': reports,
            'services': [{'id': s['id'], 'mode': s['mode'],
                          'minimum_evidence': s['minimum_evidence']} for s in services],
            'authorized_services': list(authorized),
            'api_requests': max_api_requests-remaining_api,
            'unscanned_services': unscanned,
            'phase_stats': summary,
            'note': ('DNS prefilter is not HTTP availability evidence. '
                     'Only bounded, explicitly tested provider/service pairs may be selected. '
                     'AUTH_GATE does not prove successful generation.')}
