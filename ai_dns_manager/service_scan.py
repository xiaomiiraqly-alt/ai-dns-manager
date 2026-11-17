"""Matrix of provider × service, checked at actual returned IPs; bounded parallelism."""
from concurrent.futures import ThreadPoolExecutor, Future
import copy
import threading
import time
from . import wire
from .catalogue import public_ip
from .http_checks import probe_http, ApiBudget
from .service_schema import LEVELS
from .transports import Upstream, exchange


class Memo:
    def __init__(self):self.lock=threading.Lock();self.values={}
    def get(self,key,compute):
        with self.lock:
            future=self.values.get(key)
            owner=future is None
            if owner:future=Future();self.values[key]=future
        if owner:
            try:future.set_result(compute())
            except BaseException as exc:future.set_exception(exc)
        return copy.deepcopy(future.result())


def acceptable(service,verdict):
    return verdict.get('evidence',0)>=LEVELS[service['minimum_evidence']] and verdict.get('status') in ('HTTP_OK','AUTH_GATE','PUBLIC_API_OK','AUTHENTICATED_OK','GENERATION_OK')


def scan(candidates,services,timeout=6,workers=12,round_budget=300,authorized=(),max_api_requests=8,
         environment=None,credential_providers=("reference",),preferred_endpoints=(),stop=None,dns_exchange=exchange,http_probe=probe_http,clock=time.monotonic):
    if not 1<=workers<=32 or not 1<=len(candidates)<=512 or not 1<=len(services)<=128 or not .1<=timeout<=30 or not 1<=round_budget<=1800:
        raise ValueError('Invalid scan limits')
    enabled=sorted([s for s in services if s['mode']!='off'],key=lambda s:s['mode']!='required')
    memo=Memo();deadline=clock()+round_budget
    def one(pair):
        candidate,service=pair
        row={'candidate':candidate['id'],'provider_id':candidate['provider_id'],'service':service['id'],
             'reference':candidate['provider_id']=='reference','dns':{'ok':False},'without_key':{'status':'NOT_TESTED','evidence':0},
             'with_key':{'status':'NOT_TESTED','evidence':0},'status':'NOT_TESTED','evidence':0,'eligible':False}
        if (stop and stop.is_set()) or clock()>=deadline:return dict(row,status='ROUND_BUDGET_EXHAUSTED')
        try:
            def resolve():
                start=clock();q=wire.make_query(service['domain'])
                a=dns_exchange(q,Upstream.parse(candidate['upstream']),min(timeout,max(.01,deadline-clock())))
                addresses=[public_ip(ip) for ip in wire.a_records(a)]
                return {'ok':bool(addresses),'addresses':addresses,'rcode':wire.header(a)[1]&15,'latency_ms':round((clock()-start)*1000,1)}
            row['dns']=memo.get(('dns',candidate['id'],service['domain']),resolve)
            if not row['dns']['ok']:return dict(row,status='DNS_NO_ADDRESS')
            checks=[]
            for ip in row['dns']['addresses'][:4]:
                if (stop and stop.is_set()) or clock()>=deadline:break
                def check(ip=ip):
                    return http_probe(service,ip,timeout=min(timeout,max(.01,deadline-clock())))
                checks.append(memo.get(('http',service['id'],ip),check))
            if not checks:return dict(row,status='ROUND_BUDGET_EXHAUSTED')
            best=max(checks,key=lambda r:(r.get('evidence',0),-r.get('latency_ms',1e8)))
            row['address_checks']=checks
            row['without_key']=best
            row['status'],row['evidence']=best['status'],best.get('evidence',0)
            row['latency_ms']=best.get('latency_ms',1e8)+row['dns']['latency_ms']
            row['eligible']=acceptable(service,best)
            row['partial_address_coverage']=len(checks)<len(row['dns']['addresses'])
            # Unchecked DNS answers cannot be declared service-capable: clients may
            # receive any returned A record, including addresses we never probed.
            # A later scan may choose a route only after all addresses are verified.
            if row['partial_address_coverage']:
                row['eligible']=False
                row['status']='PARTIAL_ADDRESS_COVERAGE'
            # A known failing returned address disqualifies the resolver for this service.
            if any(not acceptable(service,c) for c in checks):
                row['eligible']=False
        except (OSError,ValueError) as exc:
            row['status']='DNS_ERROR';row['dns']['error']=type(exc).__name__
        return row
    pairs=[(c,s) for s in enabled for c in candidates]
    with ThreadPoolExecutor(max_workers=workers) as pool:rows=list(pool.map(one,pairs))
    # Keyed requests are separate, explicit, budgeted and deduplicated across DNS providers.
    # Try changed/relay candidates before references so a small budget is not consumed by baselines.
    budget=ApiBudget(max_api_requests);by_service={s['id']:s for s in services}
    for row in sorted(rows,key=lambda r:((r['candidate'],r['service']) not in preferred_endpoints,r['reference'],by_service[r['service']]['mode']!='required')):
        service=by_service[row['service']]
        if service['id'] not in authorized:continue
        if (stop and stop.is_set()) or clock()>=deadline:
            row.update(status='ROUND_BUDGET_EXHAUSTED',evidence=0,eligible=False)
            continue
        if row['provider_id'] not in credential_providers:
            row['with_key']={'status':'PROBE_NOT_AUTHORIZED','evidence':0}
            row.update(status='PROBE_NOT_AUTHORIZED',evidence=0,eligible=False)
            continue
        checks=[c for c in row.get('address_checks',[]) if c.get('tls_valid')]
        if not checks:continue
        keyed=[]
        for check in checks:
            ip=check['remote_ip']
            def call(ip=ip):return http_probe(service,ip,timeout=20,authenticated=True,authorized=authorized,budget=budget,environment=environment)
            keyed.append(memo.get(('auth',service['id'],ip),call))
        best=max(keyed,key=lambda r:r.get('evidence',0))
        row['with_key']=best
        # Authorization/quota failures are not relabelled as a healthy route by the anonymous gate.
        row['status'],row['evidence']=best['status'],best.get('evidence',0)
        row['eligible']=all(acceptable(service,c) for c in keyed) and not row.get('partial_address_coverage',False)
        if row.get('partial_address_coverage'):
            row['status']='PARTIAL_ADDRESS_COVERAGE'
    references={}
    for row in rows:
        if row['reference']:references.setdefault(row['service'],set()).update(row['dns'].get('addresses',[]))
    for row in rows:
        known=references.get(row['service'],set());ips=set(row['dns'].get('addresses',[]))
        row['differs_from_reference']=bool(ips and known and not ips.intersection(known))
    return {'checked_at':time.time(),'results':rows,'services':[{'id':s['id'],'mode':s['mode'],'minimum_evidence':s['minimum_evidence']} for s in services],
            'authorized_services':list(authorized),'api_requests':max_api_requests-budget.remaining,
            'note':'Reference uses this process network, not a bypass of its VPN. AUTH_GATE is reachability only; not generation.'}
