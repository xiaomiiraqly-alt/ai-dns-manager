import copy
import unittest
from ai_dns_manager import wire
from ai_dns_manager.policy import ProviderPool, match_domain
from helpers import answer

CONFIG = {'groups': {'default': ['1.1.1.1'], 'ai': ['9.9.9.9','8.8.8.8']},
          'default_group': 'default', 'rules': [{'domain': 'example.com', 'group': 'ai'}],
          'health_interval_seconds': 0, 'failure_threshold': 1}


class RouterTests(unittest.TestCase):
    def test_suffix_boundary(self):
        self.assertTrue(match_domain('API.Example.COM.', 'example.com'))
        self.assertFalse(match_domain('fakeexample.com', 'example.com'))

    def test_longest_suffix(self):
        cfg = copy.deepcopy(CONFIG)
        cfg['rules'].append({'domain':'special.example.com','group':'default'})
        pool = ProviderPool(cfg)
        self.assertEqual(pool.group_for('x.special.example.com'), 'default')
        self.assertEqual(pool.group_for('api.example.com'), 'ai')

    def test_bad_config(self):
        for extra in ({'groups':{}}, {'timeout_seconds': float('nan')}, {'max_workers':0},
                      {'default_group':'missing'}, {'rules':[{'domain':'','group':'ai'}]}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                ProviderPool({**CONFIG, **extra})

    def test_sticky_failover_and_no_immediate_failback(self):
        calls=[]
        def mock(query, up, timeout, tcp=False):
            calls.append(up.name)
            if up.name == '9.9.9.9':
                raise TimeoutError()
            return answer(query)
        pool=ProviderPool(CONFIG, exchanger=mock)
        query=wire.make_query('example.com')
        self.assertEqual(wire.a_records(pool.exchange(query,'ai')),['203.0.113.7'])
        pool.exchange(query,'ai')
        self.assertEqual(calls,['9.9.9.9','8.8.8.8','8.8.8.8'])
        self.assertEqual(pool.snapshot()['ai']['active'],'8.8.8.8')

    def test_nxdomain_not_failure(self):
        pool=ProviderPool(CONFIG, exchanger=lambda q,u,t,**kw: answer(q,rcode=3))
        query=wire.make_query('example.com')
        self.assertEqual(wire.validate_response(query,pool.exchange(query,'ai')),3)
        self.assertEqual(pool.health['ai','9.9.9.9'].failures,0)

    def test_fail_closed_no_cross_group_fallback(self):
        calls=[]
        def failed(q,u,t,**kw):
            calls.append(u.name)
            raise TimeoutError()
        pool=ProviderPool(CONFIG, exchanger=failed)
        query=wire.make_query('example.com')
        self.assertEqual(wire.validate_response(query,pool.exchange(query,'ai')),2)
        self.assertEqual(calls,['9.9.9.9','8.8.8.8'])
        pool.exchange(query,'ai')
        self.assertEqual(len(calls),2)

    def test_recovery_needs_consecutive_probes(self):
        now=[0.0]
        pool=ProviderPool(CONFIG, clock=lambda:now[0], exchanger=lambda q,u,t,**kw:answer(q))
        pool._failure('ai','9.9.9.9','TimeoutError')
        now[0]=31
        up=pool.groups['ai'][0]
        pool._probe('ai',up)
        self.assertGreater(pool.health['ai',up.name].failures,0)
        pool._probe('ai',up)
        self.assertEqual(pool.health['ai',up.name].failures,0)

    def test_client_acl(self):
        pool=ProviderPool(CONFIG)
        self.assertTrue(pool.allowed('127.0.0.1'))
        self.assertFalse(pool.allowed('198.51.100.1'))

    def test_id_rewritten_and_returned(self):
        seen=[]
        def mock(q,u,t,**kw):
            seen.append(q)
            return answer(q)
        pool=ProviderPool(CONFIG,exchanger=mock)
        query=wire.make_query('example.com')
        result=pool.exchange(query,'ai')
        self.assertEqual(result[:2],query[:2])
        self.assertEqual(wire.question(seen[0])[:3],wire.question(query)[:3])

    def test_mismatched_question_triggers_failover(self):
        calls=[]
        def mock(q,u,t,**kw):
            calls.append(u.name)
            return answer(q[:2]+wire.make_query('attacker.invalid')[2:]) if len(calls)==1 else answer(q)
        pool=ProviderPool(CONFIG,exchanger=mock)
        query=wire.make_query('example.com')
        self.assertEqual(wire.validate_response(query,pool.exchange(query,'ai')),0)
        self.assertEqual(len(calls),2)
