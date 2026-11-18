"""Security regressions for stale authenticated plans and DNS backups."""
import json
from pathlib import Path
import tempfile
import time
import unittest
from ai_dns_manager.manager import Controller,ServicePool,settings
from ai_dns_manager.service_schema import validate_service


PROFILE=validate_service({
    'id':'gemini-api','domain':'generativelanguage.googleapis.com','mode':'required',
    'kind':'api','minimum_evidence':'generation','path':'/v1beta/models',
    'auth':{'adapter':'openai','key_env':'GEMINI_API_KEY','model_env':'GEMINI_MODEL',
            'path':'/v1beta/openai/chat/completions'}})

BASE={'groups':{'standard':['1.1.1.1']},'default_group':'standard'}


def entry(status='GENERATION_OK',evidence=4):
    return {'service':'gemini-api','candidate':'candidate-main','mode':'required',
            'upstream':{'name':'main','ip':'1.1.1.1'},
            'status':status,'evidence':evidence,'backups':[]}


def plan(route):
    return {'applicable':True,'missing_required':[],'checked_at':time.time(),
            'routes':[route]}


class ActiveEvidenceTests(unittest.TestCase):
    def test_fake_key_mandatory_route_must_never_load(self):
        pool=ServicePool(BASE,[PROFILE])
        with self.assertRaisesRegex(ValueError,'Mandatory route'):
            pool.install(plan(entry('AUTH_GATE',1)))
        self.assertEqual(pool.pools,{})

    def test_region_blocked_mandatory_route_must_never_load(self):
        pool=ServicePool(BASE,[PROFILE])
        with self.assertRaises(ValueError):
            pool.install(plan(entry('REGION_BLOCKED',4)))

    def test_unverified_backup_must_never_load(self):
        pool=ServicePool(BASE,[PROFILE])
        route=entry()
        route['backups']=[{'candidate':'bad','status':'AUTH_GATE','evidence':1,
                           'upstream':{'name':'bad','ip':'9.9.9.9'}}]
        with self.assertRaisesRegex(ValueError,'Unverified backup'):
            pool.install(plan(route))
        self.assertEqual(pool.pools,{})

    def test_verified_generation_backup_may_load(self):
        pool=ServicePool(BASE,[PROFILE])
        route=entry()
        route['backups']=[{'candidate':'good','status':'GENERATION_OK','evidence':4,
                           'upstream':{'name':'good','ip':'9.9.9.9'}}]
        pool.install(plan(route))
        self.assertIn('gemini-api',pool.pools)

    def test_restart_archives_fake_key_plan_instead_of_reusing_it(self):
        cfg,_=settings('config/manager.json')
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)
            saved=plan(entry('AUTH_GATE',1))
            saved['policy_digest']='previous-unsafe-configuration'
            (state/'active-plan.json').write_text(json.dumps(saved))
            controller=Controller(cfg,[PROFILE],tmp)
            self.assertIsNone(controller.current)
            controller.retire_unverified_snapshot()
            self.assertFalse((state/'active-plan.json').exists())
            archives=list(state.glob('unverified-plan-*.json'))
            self.assertEqual(len(archives),1)
            self.assertEqual(json.loads(archives[0].read_text())['routes'][0]['status'],'AUTH_GATE')
            controller.retire_unverified_snapshot()
            self.assertEqual(len(list(state.glob('unverified-plan-*.json'))),1)


if __name__=='__main__':
    unittest.main()
