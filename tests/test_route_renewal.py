"""Revalidating a stable mandatory route must not be blocked by optional churn."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_dns_manager.manager import Controller,ServicePool,settings
from ai_dns_manager.service_schema import validate_service
from scripts import awg_dns_gateway as gateway


def profiles():
    required=validate_service({
        'id':'gemini-api','domain':'generativelanguage.googleapis.com',
        'kind':'api','mode':'required','minimum_evidence':'generation',
        'path':'/v1beta/models',
        'auth':{'adapter':'openai','key_env':'GEMINI_API_KEY',
                'model_env':'GEMINI_MODEL','path':'/v1beta/openai/chat/completions'}
    })
    optional=validate_service({
        'id':'other-ai','domain':'other.example.com',
        'kind':'web','mode':'preferred','minimum_evidence':'http','path':'/'})
    return [required,optional]


def candidates():
    return [
        {'id':'dns-ai','provider_id':'dns-ai',
         'upstream':{'name':'dns-ai','ip':'1.1.1.1'}},
        {'id':'optional-old','provider_id':'old',
         'upstream':{'name':'optional-old','ip':'9.9.9.9'}},
        {'id':'optional-new','provider_id':'new',
         'upstream':{'name':'optional-new','ip':'8.8.8.8'}}
    ]


def result(when,optional_candidate='optional-old',gemini=True):
    rows=[
        {'candidate':'dns-ai','provider_id':'dns-ai','service':'gemini-api',
         'eligible':gemini,'status':'GENERATION_OK' if gemini else 'REGION_BLOCKED',
         'evidence':4 if gemini else 0,'latency_ms':12,
         'dns':{'addresses':['201.58.191.60']}}
    ]
    if optional_candidate:
        rows.append({'candidate':optional_candidate,'provider_id':'old' if optional_candidate=='optional-old' else 'new',
                     'service':'other-ai','eligible':True,'status':'HTTP_OK',
                     'evidence':2,'latency_ms':8,
                     'dns':{'addresses':['8.8.4.4']}})
    return {'checked_at':when,'results':rows,'api_requests':1}


class RenewalTests(unittest.TestCase):
    def _controller(self,state,now):
        cfg,_=settings('config/manager.json')
        cfg['failure_rounds']=2
        cfg['route_ttl_seconds']=1800
        scan=[result(now[0])]
        controller=Controller(cfg,profiles(),state,
                              scanner=lambda *a,**k:scan[0],
                              clock=lambda:now[0])
        return controller,scan

    def test_new_verified_gemini_renews_while_optional_switch_waits(self):
        now=[10000.]
        with tempfile.TemporaryDirectory() as tmp,patch(
                'ai_dns_manager.manager.build_catalogue',
                return_value={'candidates':candidates(),'providers':[],'sources':[]}):
            c,scan=self._controller(tmp,now)
            c.once(apply=True)
            original=c.current
            self.assertEqual(original['routes'][0]['provider_id'],'dns-ai')
            self.assertEqual(original['routes'][1]['candidate'],'optional-old')
            now[0]=10310.
            scan[0]=result(now[0],optional_candidate='optional-new')
            proposal,reason=c.once(apply=True)
            self.assertEqual(reason,'awaiting-consecutive-service-failures')
            self.assertEqual(proposal['routes'][1]['candidate'],'optional-new')
            self.assertEqual(c.current['routes'][1]['candidate'],'optional-old')
            self.assertEqual(c.current['routes'][0]['last_verified_at'],now[0])
            self.assertEqual(c.pool.route_verified['gemini-api'],now[0])
            self.assertEqual(c.pool.route_verified['other-ai'],10000.)
            self.assertEqual(c.current['checked_at'],now[0])
            self.assertEqual(json.loads((Path(tmp)/'active-plan.json').read_text())['checked_at'],now[0])

    def test_failed_generation_never_renews_primary(self):
        now=[10000.]
        with tempfile.TemporaryDirectory() as tmp,patch(
                'ai_dns_manager.manager.build_catalogue',
                return_value={'candidates':candidates(),'providers':[],'sources':[]}):
            c,scan=self._controller(tmp,now)
            c.once(apply=True)
            now[0]=10300.
            scan[0]=result(now[0],gemini=False)
            c.once(apply=True)
            self.assertEqual(c.current['checked_at'],10000.)
            self.assertEqual(c.pool.route_verified['gemini-api'],10000.)

    def test_unchecked_optional_route_does_not_gain_lifetime(self):
        now=[10000.]
        with tempfile.TemporaryDirectory() as tmp,patch(
                'ai_dns_manager.manager.build_catalogue',
                return_value={'candidates':candidates(),'providers':[],'sources':[]}):
            c,scan=self._controller(tmp,now)
            c.once(apply=True)
            now[0]=11801.
            scan[0]=result(now[0],optional_candidate='optional-new')
            c.once(apply=True)
            self.assertEqual(c.current['routes'][0]['provider_id'],'dns-ai')
            self.assertIsNone(c.current['routes'][1]['candidate'])
            self.assertNotIn('other-ai',c.pool.pools)

    def test_gateway_checks_per_service_generation_timestamp(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            stale=time.time()-2000
            current=time.time()-10
            plan={'applicable':True,'checked_at':stale,
                  'routes':[{'service':'gemini-api','provider_id':'dns-ai',
                             'candidate':'dns-ai','status':'GENERATION_OK',
                             'evidence':4,'last_verified_at':current}]}
            (base/'active-plan.json').write_text(json.dumps(plan))
            self.assertEqual(gateway.active_generation(base),'dns-ai')
            plan['routes'][0]['last_verified_at']=stale
            (base/'active-plan.json').write_text(json.dumps(plan))
            with self.assertRaisesRegex(ValueError,'expired'):
                gateway.active_generation(base)

    def test_gateway_waits_for_new_approved_proof_without_disabling_gate(self):
        from unittest.mock import patch
        with patch.object(gateway,'active_generation',side_effect=[
            ValueError('Gemini generation proof expired'),'dns-ai'
        ]) as proof,patch.object(gateway.time,'sleep'):
            self.assertEqual(gateway.await_active_generation(Path('/unused'),seconds=15),'dns-ai')
            self.assertEqual(proof.call_count,2)
        with patch.object(gateway,'active_generation',
                          side_effect=ValueError('Mandatory Gemini has no verified generation route')) as proof:
            with self.assertRaises(ValueError):
                gateway.await_active_generation(Path('/unused'),seconds=15)
            proof.assert_called_once()

    def test_no_unsafe_default_fallback(self):
        with patch.object(gateway,'active_generation',
                          side_effect=ValueError('Gemini generation proof expired')) as proof:
            with self.assertRaises(ValueError):
                gateway.await_active_generation(Path('/unused'),seconds=0)
            proof.assert_called_once()


if __name__=='__main__':
    unittest.main()
