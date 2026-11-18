"""Regression: actual Gemini generation, not AUTH_GATE, is mandatory for routing.

All network endpoints and API replies are synthetic. No user key or live API is used.
"""
import json
from pathlib import Path
import tempfile
import unittest

from ai_dns_manager import wire
from ai_dns_manager.http_checks import probe_http
from ai_dns_manager.manager import settings
from ai_dns_manager.selection import select
from ai_dns_manager.service_scan import scan
from ai_dns_manager.service_schema import load_services
from ai_dns_manager.staged_scan import staged_scan
from helpers import answer

GEMINI = next(s for s in load_services(
    json.loads(Path('config/services.json').read_text())) if s['id'] == 'gemini-api')

CANDIDATES = [
    {'id':'comss-udp', 'provider_id':'comss',
     'upstream':{'name':'comss-udp','ip':'2.2.2.2'}},
    {'id':'dns-ai-dot', 'provider_id':'dns-ai',
     'upstream':{'name':'dns-ai-dot','ip':'3.3.3.3'}},
    {'id':'reference', 'provider_id':'reference',
     'upstream':{'name':'reference','ip':'1.1.1.1'}},
    {'id':'webshift', 'provider_id':'webshift',
     'upstream':{'name':'webshift','ip':'4.4.4.4'}},
]

DNS_REPLIES = {
    '1.1.1.1': '172.217.112.4',
    '2.2.2.2': '142.251.150.2',
    '3.3.3.3': '201.58.191.60',
    '4.4.4.4': '31.31.207.68',
}


def dns_reply(query, upstream, *args):
    return answer(query, ip=DNS_REPLIES[upstream.ip])


def gateway(host, ip, path, method, headers, body, timeout):
    if headers.get('Authorization'):
        if ip == '201.58.191.60':
            return 200, b'{"choices":[{"message":{"content":"OK"}}]}', '', ip
        return 400, b'[{"error":{"message":"User location is not supported for the API use."}}]', '', ip
    return 401, b'{"error":{"message":"Invalid API key"}}', '', ip


class VerifiedGeminiTests(unittest.TestCase):
    def test_production_profile_and_legacy_policy_migration(self):
        self.assertEqual(GEMINI['minimum_evidence'], 'generation')
        cfg, services = settings('config/manager.json')
        self.assertIn('gemini-api', cfg['authorized_services'])
        self.assertIn('dns-ai', cfg['credential_provider_ids'])
        self.assertEqual(next(s for s in services if s['id']=='gemini-api')['minimum_evidence'], 'generation')
        with tempfile.TemporaryDirectory() as tmp:
            legacy = json.loads(Path('config/manager.json').read_text())
            legacy['authorized_services'] = []
            legacy['credential_provider_ids'] = ['reference']
            file = Path(tmp) / 'legacy.json'
            file.write_text(json.dumps(legacy))
            migrated, _ = settings(file)
            self.assertEqual(migrated['credential_provider_ids'], ['dns-ai'])
            self.assertEqual(migrated['authorized_services'], ['gemini-api'])

    def test_required_gemini_cannot_downgrade_to_fake_key_gate(self):
        cfg = json.loads(Path('config/manager.json').read_text())
        cfg['service_overrides']['minimum_evidence'] = {'gemini-api':'endpoint'}
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'override.json'
            p.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError,'generation evidence'):
                settings(p)

    def _scan(self, environment, allowed=('reference','comss','dns-ai','webshift')):
        responses = []
        def http(service, ip, **kwargs):
            result=probe_http(service,ip,requester=lambda *args:(responses.append(
                {'ip':args[1], 'authenticated':bool(args[4].get('Authorization'))})
                or gateway(*args)),environment=environment,**kwargs)
            return result
        def wrapped(cs,ss,**kwargs):
            return scan(cs,ss,dns_exchange=dns_reply,http_probe=http,**kwargs)
        output = staged_scan(CANDIDATES,[GEMINI],
            authorized=['gemini-api'], credential_providers=allowed,
            max_api_requests=4, required_candidates=4,
            dns_exchange=dns_reply, scanner=wrapped)
        return output, responses

    def test_auth_gate_routes_are_rejected_and_generation_wins(self):
        result, calls = self._scan({'GEMINI_API_KEY':'fake-local-test-key',
                                    'GEMINI_MODEL':'fake-model'})
        by_provider = {r['provider_id']:r for r in result['results']}
        self.assertEqual(by_provider['comss']['without_key']['status'],'AUTH_GATE')
        self.assertEqual(by_provider['comss']['status'],'REGION_BLOCKED')
        self.assertEqual(by_provider['webshift']['status'],'REGION_BLOCKED')
        self.assertEqual(by_provider['reference']['status'],'REGION_BLOCKED')
        self.assertEqual(by_provider['dns-ai']['status'],'GENERATION_OK')
        plan = select(result,[GEMINI],CANDIDATES)
        self.assertTrue(plan['applicable'])
        self.assertEqual(plan['routes'][0]['provider_id'],'dns-ai')
        self.assertEqual(plan['routes'][0]['status'],'GENERATION_OK')
        self.assertEqual(plan['routes'][0]['evidence'],4)
        self.assertEqual(plan['routes'][0]['backups'],[])
        self.assertTrue(any(c['authenticated'] for c in calls))
        self.assertNotIn('fake-local-test-key',json.dumps(result))

    def test_key_absence_cannot_mark_api_as_available(self):
        result, calls=self._scan({})
        self.assertTrue(any(row['status']=='KEY_MISSING' for row in result['results']))
        self.assertFalse(any(row['eligible'] for row in result['results']))
        plan=select(result,[GEMINI],CANDIDATES)
        self.assertFalse(plan['applicable'])
        self.assertEqual(plan['missing_required'],['gemini-api'])
        self.assertFalse(any(c['authenticated'] for c in calls))

    def test_karakeep_environment_aliases_are_accepted(self):
        verdict=probe_http(GEMINI,'201.58.191.60',
            authenticated=True,authorized=['gemini-api'],
            budget=__import__('ai_dns_manager.http_checks',fromlist=['ApiBudget']).ApiBudget(1),
            environment={'OPENAI_API_KEY':'fake-alias-key','INFERENCE_TEXT_MODEL':'fake-alias-model'},
            requester=gateway)
        self.assertEqual(verdict['status'],'GENERATION_OK')
        self.assertNotIn('fake-alias-key',json.dumps(verdict))

    def test_trusted_dns_ai_route_is_kept_in_bounded_frontier(self):
        many = [
            {'id':'other-'+str(i), 'provider_id':'other-'+str(i),
             'upstream':{'ip':'1.1.1.1','name':'other-'+str(i)}}
            for i in range(30)]
        # A previously selected other provider must not crowd the one
        # explicitly trusted for generation out of the bounded scan.
        def many_dns(q,up,*args):
            ip='201.58.191.60' if up.ip=='3.3.3.3' else '172.217.112.4'
            return answer(q,ip=ip)
        seen=[]
        def dummy(cs,ss,**kwargs):
            seen.extend(c['provider_id'] for c in cs)
            return {'results':[], 'api_requests':0}
        staged_scan(many+CANDIDATES,[GEMINI],
            authorized=['gemini-api'],credential_providers=['dns-ai'],
            preferred_endpoints=[('other-'+str(i),'gemini-api') for i in range(30)],
            required_candidates=4,dns_exchange=many_dns,scanner=dummy)
        self.assertIn('dns-ai',seen)


if __name__=='__main__':
    unittest.main()
