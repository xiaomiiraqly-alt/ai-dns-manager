import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from ai_dns_manager.service_schema import validate_service,load_services
from ai_dns_manager.http_checks import interpret,probe_http,ApiBudget
from ai_dns_manager.service_scan import scan,acceptable
from ai_dns_manager.selection import select,Stability
from ai_dns_manager.manager import ServicePool,Controller,settings
from ai_dns_manager import wire
from helpers import answer


def service(sid='gemini-api',kind='api',mode='required',level='endpoint'):
    return validate_service({'id':sid,'domain':'api.example.com' if kind=='api' else 'www.example.com','kind':kind,'mode':mode,
        'minimum_evidence':level,'path':'/v1/models','auth':{'adapter':'openai','key_env':'TEST_KEY','model_env':'TEST_MODEL','path':'/v1/chat/completions'}})


def candidates():
    return [{'id':'reference','provider_id':'reference','upstream':{'name':'reference','ip':'1.1.1.1'}},
            {'id':'relay','provider_id':'smart','upstream':{'name':'relay','ip':'9.9.9.9'}}]


def report(services,working):
    return {'checked_at':time.time(),'results':[{'candidate':c['id'],'service':s['id'],'eligible':(c['id'],s['id']) in working,
        'status':'AUTH_GATE' if (c['id'],s['id']) in working else 'REGION_BLOCKED','evidence':1,'latency_ms':10,
        'dns':{'addresses':['1.1.1.1']}} for c in candidates() for s in services]}


class ServiceSchemaTests(unittest.TestCase):
    def test_defaults_all_profiles_validate(self):
        doc=json.loads(Path('config/services.json').read_text())
        profiles=load_services(doc)
        self.assertGreaterEqual(len(profiles),40)
        self.assertTrue(any(s['id']=='gemini-api' and s['mode']=='required' for s in profiles))
    def test_modes_override_without_code(self):
        s=service()
        profiles=load_services({'schema_version':1,'services':[s]},{'modes':{s['id']:'off'}})
        self.assertEqual(profiles[0]['mode'],'off')
    def test_unknown_mode_and_service_rejected(self):
        with self.assertRaises(ValueError):load_services({'schema_version':1,'services':[service()]},{'modes':{'missing':'required'}})
        with self.assertRaises(ValueError):validate_service({**service(),'mode':'whatever'})
    def test_custom_service(self):
        extra={'id':'own-ai','domain':'own.example.org','mode':'required'}
        profiles=load_services({'schema_version':1,'services':[service()]},{'custom_services':[extra]})
        self.assertEqual(profiles[-1]['id'],'own-ai')
    def test_private_domain_and_ip_rejected(self):
        for host in ['127.0.0.1','localhost','foo.internal','bad..example.org']:
            with self.subTest(host=host),self.assertRaises(ValueError):validate_service({**service(),'domain':host})
    def test_no_literal_key_and_cross_host_credentials(self):
        s=service();s['auth']['key_env']='sk-literal-secret'
        with self.assertRaises(ValueError):validate_service(s)
        s=service();s['auth']['host']='attacker.example'
        with self.assertRaises(ValueError):validate_service(s)
    def test_duplicate_route_rejected(self):
        with self.assertRaises(ValueError):load_services({'schema_version':1,'services':[service(),{**service(),'id':'other'}]})


class HTTPVerdictTests(unittest.TestCase):
    def test_region_array(self):
        value=json.dumps([{'error':{'message':'User location is not supported for the API use.'}}]).encode()
        self.assertEqual(interpret(400,value,service())['status'],'REGION_BLOCKED')
    def test_fake_key_only_endpoint_not_generation(self):
        out=interpret(401,b'{"error":{"message":"invalid api key"}}',service())
        self.assertEqual(out['status'],'AUTH_GATE');self.assertEqual(out['evidence'],1);self.assertFalse(out['generation_ok'])
        self.assertFalse(acceptable(service(level='generation'),out))
    def test_random_403_not_healthy(self):
        self.assertEqual(interpret(403,b'forbidden',service())['evidence'],0)
    def test_bot_challenge_not_healthy_even_200(self):
        self.assertEqual(interpret(200,b'<html>Just a moment...</html>',service(kind='web'))['status'],'BOT_CHALLENGE')
    def test_content_marker_failure(self):
        s=service(kind='web');s['content_markers']=['expected']
        self.assertEqual(interpret(200,b'wrong page',s)['status'],'CONTENT_MISMATCH')
    def test_quota_and_key_not_region(self):
        self.assertEqual(interpret(429,b'{}',service(),True)['status'],'QUOTA_OR_RATE_LIMIT')
        self.assertEqual(interpret(401,b'{}',service(),True)['status'],'AUTH_OR_PERMISSION')
    def test_generation_empty_not_success(self):
        self.assertEqual(interpret(200,b'{"choices":[{"message":{"content":""}}]}',service(),True)['status'],'EMPTY_GENERATION')
    def test_generation_success(self):
        self.assertEqual(interpret(200,b'{"choices":[{"message":{"content":"OK"}}]}',service(),True)['evidence'],4)
    def test_opt_in_and_missing_key(self):
        out=probe_http(service(),'1.1.1.1',authenticated=True,environment={})
        self.assertEqual(out['status'],'PROBE_NOT_AUTHORIZED')
        out=probe_http(service(),'1.1.1.1',authenticated=True,authorized=['gemini-api'],environment={})
        self.assertEqual(out['status'],'KEY_MISSING')
    def test_secret_never_in_report(self):
        secret='a-private-key'
        def request(*args):
            self.assertEqual(args[4]['Authorization'],'Bearer '+secret)
            return 401,json.dumps({'error':{'message':'invalid api key '+secret}}).encode(),'','1.1.1.1'
        out=probe_http(service(),'1.1.1.1',authenticated=True,authorized=['gemini-api'],budget=ApiBudget(1),
            environment={'TEST_KEY':secret,'TEST_MODEL':'model'},requester=request)
        self.assertNotIn(secret,json.dumps(out));self.assertEqual(out['status'],'AUTH_OR_PERMISSION')
    def test_no_cross_host_redirect_with_key(self):
        out=probe_http(service(),'1.1.1.1',authenticated=True,authorized=['gemini-api'],budget=ApiBudget(1),
            environment={'TEST_KEY':'secret','TEST_MODEL':'model'},requester=lambda *a:(302,b'','https://evil.example/','1.1.1.1'))
        self.assertEqual(out['status'],'AUTH_REDIRECT_REFUSED')
    def test_no_cross_host_anonymous_redirect_success(self):
        out=probe_http(service(kind='web'),'1.1.1.1',requester=lambda *a:(302,b'','https://login.example/','1.1.1.1'))
        self.assertEqual(out['status'],'CROSS_HOST_REDIRECT');self.assertEqual(out['evidence'],0)
    def test_budget_and_private_ip(self):
        out=probe_http(service(),'1.1.1.1',authenticated=True,authorized=['gemini-api'],budget=ApiBudget(0),environment={'TEST_KEY':'x','TEST_MODEL':'m'})
        self.assertEqual(out['status'],'BUDGET_EXHAUSTED')
        self.assertEqual(probe_http(service(),'127.0.0.1')['status'],'UNSAFE_ADDRESS')


class SelectionTests(unittest.TestCase):
    def test_required_dominates_all_optional_weights(self):
        required=service();preferred=service('web','web','preferred','http');preferred['weight']=1000
        r=report([required,preferred],{('relay','gemini-api'),('reference','web')})
        plan=select(r,[required,preferred],candidates())
        self.assertTrue(plan['applicable']);self.assertEqual(plan['primary'],'relay')
        self.assertEqual(plan['routes'][1]['candidate'],'reference')
    def test_missing_required_never_apply(self):
        s=service();plan=select(report([s],set()),[s],candidates())
        self.assertFalse(plan['applicable']);self.assertEqual(plan['missing_required'],['gemini-api'])
    def test_off_service_not_missing(self):
        s=service(mode='off');plan=select(report([s],set()),[s],candidates())
        self.assertTrue(plan['applicable']);self.assertEqual(plan['routes'],[])
    def test_backup_must_work_for_same_service(self):
        s=service();plan=select(report([s],{('relay',s['id'])}),[s],candidates())
        self.assertEqual(plan['routes'][0]['backups'],[]);self.assertIsNone(plan['backup'])
    def test_required_services_can_use_different_providers(self):
        services=[service(),service('custom','web','required','http')]
        plan=select(report(services,{('relay','gemini-api'),('reference','custom')}),services,candidates())
        self.assertTrue(plan['applicable']);self.assertEqual({r['candidate'] for r in plan['routes']},{'relay','reference'})
    def test_healthy_route_sticky(self):
        s=service();r=report([s],{('relay',s['id']),('reference',s['id'])})
        plan=select(r,[s],candidates(),{'routes':[{'service':s['id'],'candidate':'relay'}]})
        self.assertEqual(plan['routes'][0]['candidate'],'relay')
    def test_pinned_cannot_override_required_failure(self):
        s=service();plan=select(report([s],{('relay',s['id'])}),[s],candidates(),pinned_provider='reference')
        self.assertEqual(plan['primary'],'relay')
    def test_hysteresis(self):
        old={'applicable':True,'routes':[{'service':'x','candidate':'a'}]}
        new={'applicable':True,'routes':[{'service':'x','candidate':'b'}]}
        stable=Stability(2,30)
        self.assertFalse(stable.approve(new,old,0)[0]);self.assertTrue(stable.approve(new,old,1)[0])
        self.assertFalse(stable.approve(old,new,2)[0]);self.assertFalse(stable.approve(old,new,3)[0])


class MatrixTests(unittest.TestCase):
    def test_reference_and_relay_both_checked_with_actual_addresses(self):
        calls=[]
        def dns(q,up,*a):return answer(q,ip='1.1.1.1' if up.ip=='1.1.1.1' else '9.9.9.9')
        def http(s,ip,**kw):
            calls.append(ip)
            return {'status':'AUTH_GATE','evidence':1,'tls_valid':True,'remote_ip':ip,'latency_ms':1}
        r=scan(candidates(),[service()],dns_exchange=dns,http_probe=http)
        self.assertEqual(set(calls),{'1.1.1.1','9.9.9.9'})
        self.assertTrue(r['results'][1]['differs_from_reference'])
    def test_disabled_never_probed(self):
        with patch('ai_dns_manager.service_scan.probe_http') as mock:
            r=scan(candidates(),[service(mode='off')],http_probe=mock)
            self.assertEqual(r['results'],[]);mock.assert_not_called()
    def test_deduplicate_same_ip_across_resolvers(self):
        calls=[]
        r=scan(candidates(),[service()],dns_exchange=lambda q,*a:answer(q,ip='1.1.1.1'),
            http_probe=lambda s,ip,**kw:(calls.append(ip) or {'status':'AUTH_GATE','evidence':1,'tls_valid':True,'remote_ip':ip}))
        self.assertEqual(len(calls),1)
    def test_authenticated_only_approved_provider(self):
        requests=[]
        def http(s,ip,**kw):
            if kw.get('authenticated'):requests.append(ip)
            return {'status':'GENERATION_OK' if kw.get('authenticated') else 'AUTH_GATE','evidence':4 if kw.get('authenticated') else 1,'tls_valid':True,'remote_ip':ip}
        r=scan(candidates(),[service(level='generation')],authorized=['gemini-api'],credential_providers=['smart'],
            dns_exchange=lambda q,up,*a:answer(q,ip=up.ip),http_probe=http)
        self.assertEqual(requests,['9.9.9.9'])
        self.assertFalse(r['results'][0]['eligible']);self.assertTrue(r['results'][1]['eligible'])


class RuntimePolicyTests(unittest.TestCase):
    def test_expired_or_missing_service_plan_fails_closed(self):
        cfg={'groups':{'standard':['1.1.1.1']},'default_group':'standard'}
        pool=ServicePool(cfg,[service()],ttl=60,clock=lambda:100)
        q=wire.make_query('api.example.com')
        self.assertEqual(wire.header(pool.exchange(q,'api.example.com'))[1]&15,2)
        p=select(report([service()],{('relay','gemini-api')}),[service()],candidates());p['checked_at']=0
        pool.install(p)
        self.assertEqual(wire.header(pool.exchange(q,'api.example.com'))[1]&15,2)
    def test_no_global_ipv6_change_and_suppress_unchecked_ai_hints(self):
        cfg={'groups':{'standard':['1.1.1.1']},'default_group':'standard'}
        pool=ServicePool(cfg,[service()],clock=lambda:100)
        p=select(report([service()],{('relay','gemini-api')}),[service()],candidates());p['checked_at']=100;pool.install(p)
        for kind in (28,64,65):
            q=wire.make_query('api.example.com',kind)
            self.assertEqual(wire.header(pool.exchange(q,'api.example.com'))[1]&15,0)
        with patch.object(pool.base,'exchange',return_value=b'ordinary'):
            self.assertEqual(pool.exchange(wire.make_query('ordinary.example',28),'ordinary.example'),b'ordinary')
    def test_incomplete_plan_cannot_replace_current(self):
        cfg={'groups':{'standard':['1.1.1.1']},'default_group':'standard'}
        pool=ServicePool(cfg,[service()])
        with self.assertRaises(ValueError):pool.install({'applicable':False,'missing_required':['gemini-api']})

class ExtraSecurityTests(unittest.TestCase):
    def test_tls_failure_prevents_sending_headers(self):
        import ssl
        from ai_dns_manager.http_checks import https_request
        with patch('ai_dns_manager.http_checks.PinnedHTTPS') as cls:
            cls.return_value.connect.side_effect=ssl.SSLCertVerificationError('bad name')
            with self.assertRaises(ssl.SSLCertVerificationError):
                https_request('api.example.com','1.1.1.1','/',headers={'Authorization':'secret'})
            cls.return_value.request.assert_not_called()
    def test_json_adapter_requires_real_field(self):
        s=service();s['auth']={'adapter':'json','key_env':'KEY','path':'/account','success_pointer':'/username','method':'GET'}
        self.assertEqual(interpret(200,b'{"username":"user"}',s,True)['status'],'AUTHENTICATED_OK')
        self.assertEqual(interpret(200,b'{}',s,True)['evidence'],0)
    def test_anthropic_nonempty_text(self):
        s=service();s['auth']['adapter']='anthropic'
        self.assertEqual(interpret(200,b'{"content":[{"type":"text","text":"OK"}]}',s,True)['evidence'],4)
    def test_unauthorized_provider_cannot_replace_key_failure(self):
        def http(s,ip,**kw):
            return {'status':'AUTH_OR_PERMISSION' if kw.get('authenticated') else 'AUTH_GATE',
                    'evidence':0 if kw.get('authenticated') else 1,'tls_valid':True,'remote_ip':ip}
        r=scan(candidates(),[service()],authorized=['gemini-api'],credential_providers=['reference'],
            dns_exchange=lambda q,up,*a:answer(q,ip=up.ip),http_probe=http)
        self.assertTrue(all(not row['eligible'] for row in r['results']))
        self.assertFalse(select(r,[service()],candidates())['applicable'])
    def test_cancelled_scan_skips_network(self):
        import threading
        stop=threading.Event();stop.set()
        with patch('ai_dns_manager.service_scan.exchange') as net:
            r=scan(candidates(),[service()],stop=stop,dns_exchange=net)
            net.assert_not_called()
            self.assertTrue(all(row['status']=='ROUND_BUDGET_EXHAUSTED' for row in r['results']))
    def test_multi_service_hysteresis_counts_all_each_round(self):
        old={'applicable':True,'routes':[{'service':x,'candidate':'a'} for x in ('x','y')]}
        new={'applicable':True,'routes':[{'service':x,'candidate':'b'} for x in ('x','y')]}
        stable=Stability(2,30)
        self.assertFalse(stable.approve(new,old,0)[0]);self.assertTrue(stable.approve(new,old,1)[0])
    def test_manager_config_valid_without_network(self):
        with patch('socket.create_connection') as net:
            cfg,defs=settings('config/manager.json')
            self.assertEqual(len(defs),44);net.assert_not_called()


class ControllerIntegrationTests(unittest.TestCase):
    def test_dry_scan_no_active_state_and_failed_round_preserves_plan(self):
        cfg,_=settings('config/manager.json');defs=[service()]
        fake_catalogue={'candidates':candidates(),'providers':[],'sources':[]}
        success=report(defs,{('relay','gemini-api')})
        with tempfile.TemporaryDirectory() as tmp,patch('ai_dns_manager.manager.build_catalogue',return_value=fake_catalogue):
            controller=Controller(cfg,defs,tmp,scanner=lambda *a,**k:success)
            controller.once(apply=False)
            self.assertFalse((Path(tmp)/'active-plan.json').exists())
            controller.once(apply=True)
            active=(Path(tmp)/'active-plan.json').read_bytes()
            controller.scanner=lambda *a,**k:report(defs,set())
            plan,_=controller.once(apply=True)
            self.assertFalse(plan['applicable']);self.assertEqual((Path(tmp)/'active-plan.json').read_bytes(),active)
    def test_settings_change_rejects_previous_saved_plan(self):
        cfg,_=settings('config/manager.json')
        # This fixture checks the legacy unauthenticated plan reload path.
        # Production Gemini uses authorized generation and must recheck on
        # every process restart rather than reviving saved keyed evidence.
        cfg['authorized_services']=[]
        defs=[service()]
        fake={'candidates':candidates(),'providers':[],'sources':[]}
        with tempfile.TemporaryDirectory() as tmp,patch('ai_dns_manager.manager.build_catalogue',return_value=fake):
            controller=Controller(cfg,defs,tmp,scanner=lambda *a,**k:report(defs,{('relay','gemini-api')}))
            controller.once(apply=True)
            self.assertIsNotNone(Controller(cfg,defs,tmp).current)
            defs[0]['minimum_evidence']='generation'
            self.assertIsNone(Controller(cfg,defs,tmp).current)

class CompletePathTests(unittest.TestCase):
    def test_scan_select_and_real_dns_forwarding(self):
        import socketserver
        from helpers import running,UDP
        upstream=socketserver.UDPServer(('127.0.0.1',0),UDP);upstream.calls=0;upstream.truncated=False
        with running(upstream):
            candidate={'id':'test-route','provider_id':'test','upstream':{'name':'fixture','ip':'127.0.0.1','port':upstream.server_address[1]}}
            result=scan([candidate],[service()],http_probe=lambda s,ip,**kw:{'status':'AUTH_GATE','evidence':1,'tls_valid':True,'remote_ip':ip},
                        dns_exchange=lambda q,*a:answer(q,ip='1.1.1.1'))
            plan=select(result,[service()],[candidate])
            pool=ServicePool({'groups':{'default':['1.1.1.1']},'default_group':'default'},[service()]);pool.install(plan)
            q=wire.make_query('api.example.com')
            self.assertEqual(wire.a_records(pool.exchange(q,'api.example.com')),['203.0.113.7'])
            self.assertEqual(upstream.calls,1)

class FakeCredentialTests(unittest.TestCase):
    def test_custom_api_header_without_real_key(self):
        s=service('custom-api');s['auth']['auth_header']='xi-api-key';s['auth']['auth_prefix']=''
        def req(*args):
            self.assertEqual(args[4]['xi-api-key'],'ai-dns-manager-invalid-key')
            return 401,b'{"error":{"message":"invalid api key"}}','','1.1.1.1'
        out=probe_http(s,'1.1.1.1',environment={'TEST_KEY':'must-not-be-sent'},requester=req)
        self.assertEqual(out['status'],'AUTH_GATE')
    def test_post_only_anonymous_probe(self):
        s=service();s.update(method='POST',body={'model':'placeholder'})
        def req(*args):
            self.assertEqual(args[3],'POST');self.assertEqual(json.loads(args[5]),{'model':'placeholder'})
            return 401,b'{"error":{"message":"invalid api key"}}','','1.1.1.1'
        self.assertEqual(probe_http(s,'1.1.1.1',requester=req)['evidence'],1)
