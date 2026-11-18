"""Real incident: 12 unauthorized required candidates, zero API requests, no Gemini route.

These fixtures never use a real API key or external network. The regression
must preserve the original credential allowlist, not widen it automatically.
"""
import json
from pathlib import Path
import tempfile
import unittest

from ai_dns_manager.catalogue import build_catalogue,merge_catalogues,normalize_provider
from ai_dns_manager.service_schema import load_services
from ai_dns_manager.staged_scan import staged_scan
from ai_dns_manager.service_scan import scan
from ai_dns_manager import wire
from helpers import answer


GEMINI=next(x for x in load_services(json.loads(Path('config/services.json').read_text()))
            if x['id']=='gemini-api')


def candidate(i,provider,ip):
    return {'id':'candidate-'+str(i),'provider_id':provider,
            'upstream':{'ip':ip,'name':'candidate-'+str(i)}}


class TrustedFrontierRecoveryTests(unittest.TestCase):
    def test_local_trusted_dns_ai_keeps_identity_and_exclusive_endpoints(self):
        local=normalize_provider(
            {'id':'dns-ai','name':'Trusted DNS-AI','hosts':['dns.dns-ai.ru'],
             'ipv4':['194.87.196.13','45.151.102.219']},'local')
        remote_same_id=normalize_provider(
            {'id':'dns-ai','ipv4':['8.8.8.8']},'remote')
        remote_looks_same=normalize_provider(
            {'id':'alias','hosts':['dns.dns-ai.ru'],
             'ipv4':['194.87.196.13','9.9.9.9']},'remote')
        merged=merge_catalogues([local,remote_same_id,remote_looks_same])
        trusted=next(x for x in merged if x['id']=='dns-ai' and 'local' in x['sources'])
        self.assertEqual(trusted['ipv4'],['194.87.196.13','45.151.102.219'])
        self.assertEqual(trusted['sources'],['local'])

    def test_catalogue_local_identity_survives_seed_feed_collisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings={
                'sources':[{'id':'external','format':'aidns-v1','refresh_seconds':21600,
                            'urls':['https://raw.githubusercontent.com/example/repo/main/data.json']}],
                'baselines':[],'discover_addresses':False,
                'custom_providers':[{'id':'dns-ai','hosts':['dns.dns-ai.ru'],
                                     'ipv4':['194.87.196.13','45.151.102.219']}]
            }
            evil={'schemaVersion':1,'providers':[
                {'id':'dns-ai','name':'Impersonation','ipv4':['8.8.8.8']},
                {'id':'evil-alias','ipv4':['194.87.196.13','9.9.9.9']}
            ]}
            result=build_catalogue(
                settings,Path(tmp),Path('config/providers.seed.json'),
                fetcher=lambda _:json.dumps(evil).encode())
            ids=[x['provider_id'] for x in result['candidates']]
            self.assertIn('dns-ai',ids)
            dns_ai=[x for x in result['candidates'] if x['provider_id']=='dns-ai']
            self.assertTrue(dns_ai)
            for x in dns_ai:
                upstream=x['upstream']
                self.assertIn(upstream.get('ip') or upstream.get('bootstrap_ip'),
                              ('194.87.196.13','45.151.102.219'))
            self.assertNotIn('8.8.8.8',[x['upstream'].get('ip') for x in dns_ai])

    def test_unauthorized_fast_resolvers_never_consume_keyed_frontier(self):
        cs=[candidate(i,'other-'+str(i),'1.1.1.1') for i in range(25)]
        cs += [candidate(26,'dns-ai','9.9.9.9')]
        calls=[]
        def dns(q,up,*a):
            calls.append(up.ip)
            return answer(q,ip='201.58.191.60' if up.ip=='9.9.9.9'
                          else '142.251.150.2')
        triggered=[]
        def http(service,ip,**kw):
            triggered.append((ip,bool(kw.get('authenticated'))))
            if kw.get('authenticated'):
                kw['budget'].take()
                return {'status':'GENERATION_OK','evidence':4,'generation_ok':True,
                        'tls_valid':True,'remote_ip':ip}
            return {'status':'AUTH_GATE','evidence':1,'tls_valid':True,'remote_ip':ip}
        def scanner(c,s,**opts):
            return scan(c,s,dns_exchange=dns,http_probe=http,**opts)
        result=staged_scan(cs,[GEMINI],authorized=['gemini-api'],
            credential_providers=['dns-ai'],required_candidates=12,
            max_api_requests=4,dns_exchange=dns,scanner=scanner)
        self.assertEqual({r['provider_id'] for r in result['results']},{'dns-ai'})
        self.assertEqual(result['results'][0]['status'],'GENERATION_OK')
        self.assertEqual(result['phase_stats']['required_tested'],1)
        self.assertTrue(result['phase_stats']['required_ok'])
        self.assertEqual(result['api_requests'],1)
        self.assertIn(('201.58.191.60',True),triggered)

    def test_trusted_dns_prewarm_uses_longer_retry_but_no_false_success(self):
        cs=[candidate(i,'other-'+str(i),'1.1.1.1') for i in range(12)]
        cs += [candidate(25,'dns-ai','9.9.9.9')]
        attempts=[]
        def dns(q,up,timeout,*a):
            if up.ip=='9.9.9.9':
                attempts.append(timeout)
                if len(attempts)==1:raise TimeoutError('Transient cheap prefilter')
                return answer(q,ip='201.58.191.60')
            return answer(q,ip='142.251.150.2')
        def fake_scanner(c,s,**kw):
            self.assertEqual([x['provider_id'] for x in c],['dns-ai'])
            return {'results':[{'candidate':c[0]['id'],'provider_id':'dns-ai',
                                'service':'gemini-api','eligible':True,
                                'status':'GENERATION_OK','evidence':4,
                                'dns':{'addresses':['201.58.191.60']}}],
                    'api_requests':1}
        result=staged_scan(cs,[GEMINI],authorized=['gemini-api'],
            credential_providers=['dns-ai'],required_candidates=12,
            dns_exchange=dns,scanner=fake_scanner)
        self.assertEqual(len(attempts),2)
        self.assertGreater(attempts[1],attempts[0])
        self.assertTrue(result['phase_stats']['required_ok'])
        self.assertEqual(result['phase_stats']['trusted_dns_live'],1)

    def test_all_trusted_dns_unreachable_remains_fail_closed(self):
        cs=[candidate(i,'other-'+str(i),'1.1.1.1') for i in range(12)]
        cs += [candidate(25,'dns-ai','9.9.9.9')]
        def dns(q,up,*a):
            if up.ip=='9.9.9.9':raise TimeoutError('Trusted DNS down')
            return answer(q,ip='142.251.150.2')
        calls=[]
        def fake_scanner(c,s,**kwargs):
            calls.append(c)
            return {'results':[],'api_requests':0}
        result=staged_scan(cs,[GEMINI],authorized=['gemini-api'],
            credential_providers=['dns-ai'],dns_exchange=dns,scanner=fake_scanner)
        self.assertEqual(calls,[])
        self.assertEqual(result['api_requests'],0)
        self.assertEqual(result['phase_stats']['trusted_candidates'],1)
        self.assertEqual(result['phase_stats']['trusted_dns_live'],0)
        self.assertFalse(result['phase_stats']['required_ok'])
        self.assertEqual(result['phase_stats']['required_missing'],['gemini-api'])

    def test_anonymous_required_service_still_scans_all_providers(self):
        service=dict(GEMINI, minimum_evidence='endpoint')
        # No keyed-generation requirement: keep ordinary provider discovery.
        cs=[candidate(0,'other','1.1.1.1')]
        def fake_scanner(c,s,**opts):
            return {'results':[{'candidate':c[0]['id'],'provider_id':'other',
                                'service':'gemini-api','eligible':True,
                                'status':'AUTH_GATE','evidence':1,
                                'dns':{'addresses':['142.251.150.2']}}],
                    'api_requests':0}
        result=staged_scan(cs,[service],authorized=[],
            credential_providers=['dns-ai'],dns_exchange=lambda q,*a:answer(q,ip='142.251.150.2'),
            scanner=fake_scanner)
        self.assertTrue(result['phase_stats']['required_ok'])
        self.assertEqual(result['phase_stats']['required_tested'],1)


if __name__=='__main__':
    unittest.main()
