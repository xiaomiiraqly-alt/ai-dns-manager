"""Service-aware scan/plan/watch/serve. No host DNS, firewall, or VPN mutations."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import logging
from pathlib import Path
import signal
import threading
import time
from .catalogue import atomic_json,build_catalogue,download
from .transports import Upstream,exchange
from .policy import ProviderPool,event
from .selection import select,Stability
from .service_schema import load_services
from .service_scan import scan
from .staged_scan import staged_scan
from .server import ThreadedUDP,ThreadedTCP,UDPHandler,TCPHandler
from . import wire

ROOT=Path(__file__).resolve().parents[1]


def read_json(path,limit=1048576):
    p=Path(path)
    if p.stat().st_size>limit:raise ValueError('Config/state exceeds size limit')
    return json.loads(p.read_text())


def settings(path):
    cfg=read_json(path)
    if cfg.get('schema_version')!=1:raise ValueError('Invalid manager schema')
    for key,default,low,high in [('scan_interval_seconds',300,60,86400),('round_budget_seconds',300,1,1800),
                               ('route_ttl_seconds',1800,60,86400),('workers',12,1,32),('max_api_requests',8,0,128),
                               ('failure_rounds',2,1,10),('switch_cooldown_seconds',300,0,86400)]:
        n=cfg.setdefault(key,default)
        if isinstance(n,bool) or not isinstance(n,int) or not low<=n<=high:raise ValueError('Invalid '+key)
    cfg.setdefault('authorized_services',[]);cfg.setdefault('credential_provider_ids',['reference'])
    cfg.setdefault('service_overrides',{})
    scan_policy=cfg.setdefault('scan_strategy',{})
    if not isinstance(scan_policy,dict):raise ValueError('Invalid scan strategy')
    for key,default,low,high in [('required_candidates',12,1,32),('preferred_candidates',4,1,16),
                                 ('required_seconds',55,1,900),('preferred_seconds',75,1,900)]:
        value=scan_policy.setdefault(key,default)
        if isinstance(value,bool) or not isinstance(value,int) or not low<=value<=high:
            raise ValueError('Invalid scan strategy: '+key)
    for key,default,low,high in [('dns_timeout',1.5,.1,8),('http_timeout',2.5,.1,10)]:
        value=scan_policy.setdefault(key,default)
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not low<=value<=high:
            raise ValueError('Invalid scan strategy: '+key)
    if not isinstance(cfg['authorized_services'],list) or not isinstance(cfg['credential_provider_ids'],list):raise ValueError('Invalid credential authorization settings')
    services=load_services(read_json(ROOT/'config/services.json'),cfg['service_overrides'])
    known={s['id']:s for s in services}
    if any(s not in known or not known[s].get('auth') for s in cfg['authorized_services']):raise ValueError('Unknown or unsupported authenticated service')
    # Gemini is mandatory for this deployment. A fake-key AUTH_GATE was shown
    # to be a false positive (Comss, WebShift and ZombieDNS), while a real
    # model response succeeded only via DNS-AI. Keep operator-controlled
    # profile and provider allowlists but never downgrade this required API.
    gemini=known.get('gemini-api')
    if gemini and gemini['mode']=='required':
        if gemini['minimum_evidence']!='generation':
            raise ValueError('Required Gemini API must use generation evidence')
        auth=gemini.get('auth')
        if not auth:
            raise ValueError('Required Gemini API lacks an authenticated generation adapter')
        # Existing local/manager.json files predate v0.6 and had empty
        # authorized_services and reference-only credential providers. Apply
        # this known requested policy to them without overwriting user files.
        cfg['authorized_services']=list(dict.fromkeys(cfg['authorized_services']+['gemini-api']))
        cfg['credential_provider_ids']=list(dict.fromkeys(cfg['credential_provider_ids']+['dns-ai']))
    # Nothing above creates credentials: the manager fails closed until a
    # separate, root-owned env file is explicitly mounted at installation.

    # Validate baseline DNS settings before any network activity.
    ProviderPool(cfg['router'])
    return cfg,services


class ServicePool:
    """Atomically swap private per-service pools; monitored unavailable routes fail closed."""
    def __init__(self,base,services,ttl=1800,clock=time.time):
        self.base=ProviderPool(base);self.base_config=copy.deepcopy(base)
        self.timeout=self.base.timeout;self.slots=self.base.slots;self.lock=threading.RLock()
        self.clock=clock;self.ttl=ttl;self.pools={};self.checked_at=0
        self.domains=sorted([(d,s['id']) for s in services if s['mode']!='off' for d in s['routes']],key=lambda x:len(x[0]),reverse=True)
    def allowed(self,ip):return self.base.allowed(ip)
    def group_for(self,domain):return domain
    def install(self,plan):
        if not plan.get('applicable') or plan.get('missing_required'):raise ValueError('Incomplete required coverage')
        pools={}
        for route in plan['routes']:
            if not route.get('candidate'):continue
            upstreams=[route['upstream']]+[b['upstream'] for b in route['backups']]
            cfg={**self.base_config,'default_group':'selected','groups':{'selected':upstreams},'rules':[],'health_interval_seconds':0}
            pools[route['service']]=ProviderPool(cfg)
        with self.lock:self.pools=pools;self.checked_at=plan['checked_at']
    def exchange(self,packet,domain,tcp=False):
        selected=next((sid for suffix,sid in self.domains if domain==suffix or domain.endswith('.'+suffix)),None)
        if selected is None:return self.base.exchange(packet,self.base.group_for(domain),tcp)
        with self.lock:pool=self.pools.get(selected);valid=0<=self.clock()-self.checked_at<=self.ttl
        if pool is None or not valid:return wire.reply(packet)
        # Encrypted DNS may still return direct IPv6/HTTPS hints. Service-aware policies currently
        # validate IPv4 HTTPS; suppress AAAA and HTTPS/SVCB hints to prevent an untested parallel path.
        qtype=wire.question(packet)[1]
        if qtype in (28,64,65):return wire.reply(packet,0)
        return pool.exchange(packet,'selected',tcp)


class Controller:
    def __init__(self,cfg,services,state_dir,fetcher=None,resolver=None,scanner=None,clock=time.time):
        self.cfg=cfg;self.services=services;self.state=Path(state_dir);self.clock=clock
        self.fetcher=fetcher;self.resolver=resolver;self.scanner=scanner or staged_scan;self.scan_cycle=0
        self.stability=Stability(cfg['failure_rounds'],cfg['switch_cooldown_seconds'])
        self.pool=ServicePool(cfg['router'],services,cfg['route_ttl_seconds'],clock)
        self.current=None
        self.state.mkdir(parents=True,exist_ok=True,mode=0o700)
        # Settings changes invalidate previous evidence; do not load a plan for a different service policy.
        import hashlib
        self.policy_digest=hashlib.sha256(json.dumps({'services':services,'providers':cfg['providers'],'authorized':cfg['authorized_services'],
            'credential_providers':cfg['credential_provider_ids']},sort_keys=True).encode()).hexdigest()
        try:
            saved=read_json(self.state/'active-plan.json',4194304)
            if not cfg['authorized_services'] and saved.get('policy_digest')==self.policy_digest and 0<=clock()-saved['checked_at']<=cfg['route_ttl_seconds']:
                self.pool.install(saved);self.current=saved
        except (OSError,ValueError,KeyError,TypeError):pass
    def once(self,offline=False,refresh=False,apply=False,stop=None):
        atomic_json(self.state/'scan-progress.json',{'phase':'provider_catalogue','timestamp':time.time()})
        def fetch(url):
            if stop and stop.is_set():raise InterruptedError()
            return (self.fetcher or download)(url)
        def resolve(host):
            if stop and stop.is_set():return []
            if self.resolver:return self.resolver(host)
            found=[]
            for baseline in self.cfg['providers']['baselines'][:2]:
                if stop and stop.is_set():break
                try:found+=wire.a_records(exchange(wire.make_query(host),Upstream.parse(baseline),2))
                except (OSError,ValueError):continue
            return found
        options={'resolver':resolve,'fetcher':fetch}
        catalogue=build_catalogue(self.cfg['providers'],self.state/'cache',ROOT/'config/providers.seed.json',offline,refresh,**options)
        if stop and stop.is_set():raise InterruptedError()
        atomic_json(self.state/'catalogue.json',catalogue)
        scan_options={'workers':self.cfg['workers'],
            'round_budget':self.cfg['round_budget_seconds'],'authorized':self.cfg['authorized_services'],
            'max_api_requests':self.cfg['max_api_requests'],'credential_providers':self.cfg['credential_provider_ids'],
            'preferred_endpoints':[(r['candidate'],r['service']) for r in (self.current or {}).get('routes',[])
                                   if r.get('candidate')], 'stop':stop}
        if self.scanner is staged_scan:
            def progress(summary):
                atomic_json(self.state/'scan-progress.json',summary)
                event('scan_progress',**summary)
            scan_options.update(self.cfg.get('scan_strategy',{}))
            scan_options.update({'progress':progress,'cycle':self.scan_cycle})
        report=self.scanner(catalogue['candidates'],self.services,**scan_options)
        self.scan_cycle+=1
        if stop and stop.is_set():raise InterruptedError()
        plan=select(report,self.services,catalogue['candidates'],self.current,self.cfg.get('pinned_provider'))
        plan['policy_digest']=self.policy_digest
        atomic_json(self.state/'service-report.json',report)
        atomic_json(self.state/'proposed-plan.json',plan)
        approved,reason=self.stability.approve(plan,self.current,self.clock())
        if apply and approved:
            # Persist only after validation; replace the running plan only as a complete transaction.
            trial=ServicePool(self.cfg['router'],self.services,self.cfg['route_ttl_seconds']);trial.install(plan)
            atomic_json(self.state/'active-plan.json',plan);self.pool.install(plan);self.current=plan
        event('service_selection',applicable=plan['applicable'],missing_required=plan['missing_required'],applied=bool(apply and approved),reason=reason,
            generation_confirmed=sum(r['status']=='GENERATION_OK' for r in plan['routes']))
        return plan,reason
    def monitor(self,stop,offline=False):
        while not stop.is_set():
            started=self.clock()
            try:self.once(offline=offline,apply=True,stop=stop)
            except Exception as exc:
                # Do not leak request bodies, credentials or URLs through exception messages.
                atomic_json(self.state/'scan-progress.json',{'phase':'error','error_type':type(exc).__name__,'timestamp':time.time()})
                event('selection_cycle_error',error=type(exc).__name__)
            if stop.wait(max(1,self.cfg['scan_interval_seconds']-(self.clock()-started))):break


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['scan','serve','validate','status'])
    p.add_argument('--config',default=str(ROOT/'config/manager.json'))
    p.add_argument('--state-dir',default='data/service-manager')
    p.add_argument('--offline',action='store_true',help='Do not download catalogues or discover provider host IPs; network service probes still run')
    p.add_argument('--refresh',action='store_true')
    p.add_argument('--listen',default='127.0.0.1')
    p.add_argument('--port',type=int,default=5353)
    args=p.parse_args();logging.basicConfig(level=logging.INFO,format='%(message)s')
    try:
        cfg,services=settings(args.config)
        if args.action=='validate':
            print(json.dumps({'services':len(services),'required':[s['id'] for s in services if s['mode']=='required'],
                'preferred':[s['id'] for s in services if s['mode']=='preferred'],'authenticated':cfg['authorized_services']}));return
        controller=Controller(cfg,services,args.state_dir)
        if args.action=='status':
            if controller.current:
                print(json.dumps(controller.current,indent=2));return
            try:progress=read_json(controller.state/'scan-progress.json')
            except (OSError,ValueError):progress={'phase':'not_started'}
            print(json.dumps({'status':'NO_VALID_SERVICE_PLAN','scan':progress},indent=2));return
        if args.action=='scan':
            plan,reason=controller.once(args.offline,args.refresh,apply=False)
            print(json.dumps({'applicable':plan['applicable'],'missing_required':plan['missing_required'],
                'routes':[{'service':r['service'],'status':r['status'],'provider':r.get('provider_id')} for r in plan['routes']],
                'state_dir':args.state_dir,'applied':False},indent=2));return
        import ipaddress
        ipaddress.IPv4Address(args.listen)
        if not 1<=args.port<=65535:raise ValueError('Invalid listener port')
        stop=threading.Event();servers=[];threads=[]
        try:
            for cls,handler in [(ThreadedUDP,UDPHandler),(ThreadedTCP,TCPHandler)]:
                server=cls((args.listen,args.port),handler);server.pool=controller.pool;servers.append(server)
            for server in servers:
                t=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.1},daemon=True);t.start();threads.append(t)
            for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
            worker=threading.Thread(target=controller.monitor,args=(stop,args.offline),daemon=True);worker.start()
            event('service_manager_listening',port=args.port,address=args.listen);stop.wait()
        finally:
            stop.set()
            for server,_ in zip(servers,threads):server.shutdown()
            for server in servers:server.server_close()
    except (OSError,ValueError,KeyError,TypeError) as exc:p.exit(1,'Manager error: '+type(exc).__name__+'\n')


if __name__=='__main__':main()
