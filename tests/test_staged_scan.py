"""Budget, phase-order, fail-closed and progress regressions for real VPS scale."""
import threading
import time
import unittest
from ai_dns_manager import wire
from ai_dns_manager.staged_scan import staged_scan, _frontier
from ai_dns_manager.service_scan import scan
from helpers import answer


def service(index=0, mode='preferred'):
    return {'id': 'service-'+str(index), 'domain': 'api.example.com',
            'mode': mode, 'kind': 'api', 'minimum_evidence': 'endpoint',
            'path': '/v1/models', 'weight': 1}


def candidates(count=136):
    return [{'id': 'provider-'+str(i), 'provider_id': 'reference' if i == 0 else 'smart-'+str(i),
             'upstream': {'ip': '1.1.1.1', 'name': 'provider-'+str(i)}} for i in range(count)]


def fake_result(cs, ss, **kw):
    return {'api_requests': 0,
            'results': [{'candidate': c['id'], 'provider_id': c['provider_id'],
                         'service': s['id'], 'status': 'AUTH_GATE',
                         'evidence': 1, 'eligible': True, 'dns': {'addresses': ['8.8.4.4']},
                         'latency_ms': 1}
                        for c in cs for s in ss]}


class StagedScanTests(unittest.TestCase):
    def test_large_matrix_is_bounded_and_required_first(self):
        calls, checkpoints = [], []
        def scanner(cs, ss, **kw):
            calls.append((len(cs),len(ss), tuple(s['mode'] for s in ss), kw))
            return fake_result(cs,ss,**kw)
        result = staged_scan(candidates(136),
                             [service(0,'required')]+[service(i) for i in range(1,44)],
                             scanner=scanner, dns_exchange=lambda q,*a:answer(q,ip='8.8.4.4'),
                             progress=checkpoints.append)
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[0][1],1)
        self.assertTrue(all(m == 'required' for m in calls[0][2]))
        self.assertTrue(all(m == 'preferred' for m in calls[1][2]))
        self.assertLessEqual(calls[0][0],12)
        self.assertLessEqual(calls[1][0],4)
        self.assertLessEqual(len(result['results']),12+4*43)
        self.assertEqual(result['phase_stats']['candidates'],136)
        self.assertEqual(result['phase_stats']['dns_live'],136)
        self.assertEqual([p['phase'] for p in checkpoints],
                         ['dns_prefilter','required_services','preferred_services','complete'])

    def test_required_route_can_be_found_without_optional_route_success(self):
        def scanner(cs,ss,**kw):
            if ss[0]['mode']=='preferred':
                return {'results':[], 'api_requests':0}
            return fake_result(cs,ss,**kw)
        r=staged_scan(candidates(30),[service(0,'required'),service(1)],
                      scanner=scanner,dns_exchange=lambda q,*a:answer(q,ip='8.8.4.4'))
        self.assertIn('service-1',r['unscanned_services'])
        self.assertNotIn('service-0',r['unscanned_services'])
        self.assertFalse(any(x['service']=='service-1' for x in r['results']))

    def test_failed_required_never_claims_healthy_route(self):
        def scanner(cs,ss,**kw):
            return {'results':[dict(x,eligible=False,status='REGION_BLOCKED',evidence=0)
                               for x in fake_result(cs,ss,**kw)['results']], 'api_requests':0}
        r=staged_scan(candidates(16),[service(0,'required'),service(1)],
                      scanner=scanner,dns_exchange=lambda q,*a:answer(q,ip='8.8.4.4'))
        self.assertFalse(any(x['eligible'] for x in r['results']))

    def test_all_dns_dead_returns_report_without_applying(self):
        r=staged_scan(candidates(20),[service(0,'required'),service(1)],
                      dns_exchange=lambda *a:(_ for _ in ()).throw(TimeoutError()))
        self.assertEqual(r['results'],[])
        self.assertEqual(r['phase_stats']['dns_live'],0)
        self.assertEqual(r['unscanned_services'],['service-0','service-1'])

    def test_cancel_skips_network(self):
        stopped=threading.Event();stopped.set()
        attempted=[]
        r=staged_scan(candidates(136),[service(0,'required')],
                      stop=stopped,
                      dns_exchange=lambda *a:attempted.append(1))
        self.assertEqual(attempted,[])
        self.assertEqual(r['results'],[])

    def test_only_public_dns_answers_qualify_for_frontier(self):
        r=staged_scan(candidates(8),[service(0,'required')],
                      dns_exchange=lambda q,*a:answer(q,ip='127.0.0.1'))
        self.assertEqual(r['phase_stats']['dns_live'],0)

    def test_previous_candidate_kept_when_responsive(self):
        rows=[{'candidate':c, 'addresses':('8.8.4.4',),
               'latency_ms':i} for i,c in enumerate(candidates(5))]
        chosen=_frontier(rows,2,previous=('provider-4',))
        self.assertEqual(chosen[0]['id'],'provider-4')

    def test_invalid_budget_and_limits_are_rejected(self):
        for options in ({'required_candidates':0},{'preferred_candidates':17},
                        {'workers':0},{'http_timeout':60},{'round_budget':0}):
            with self.subTest(options=options),self.assertRaises(ValueError):
                staged_scan(candidates(1),[service(0,'required')],**options)

    def test_real_scanner_integration_respects_evidence(self):
        # The staged wrapper must not manufacture HTTP eligibility itself.
        def real(cs,ss,**kw):
            return scan(cs,ss,dns_exchange=lambda q,*a:answer(q,ip='8.8.4.4'),
                        http_probe=lambda s,ip,**k:{'status':'REGION_BLOCKED','evidence':0,
                        'tls_valid':True,'remote_ip':ip}, **kw)
        r=staged_scan(candidates(6),[service(0,'required')],scanner=real,
                      dns_exchange=lambda q,*a:answer(q,ip='8.8.4.4'))
        self.assertFalse(any(row['eligible'] for row in r['results']))


if __name__ == '__main__':
    unittest.main()
