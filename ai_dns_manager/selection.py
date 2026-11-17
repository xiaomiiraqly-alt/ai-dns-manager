"""Required > all preferred combined, per-service routes, same-service backups and sticky choice."""
import statistics
import time
from .http_checks import NON_ROUTING


def select(report,services,candidates,previous=None,pinned_provider=None):
    byid={c['id']:c for c in candidates}
    active=[s for s in services if s['mode']!='off']
    rows={(r['candidate'],r['service']):r for r in report['results']}
    required=[s for s in active if s['mode']=='required']
    preferred=[s for s in active if s['mode']=='preferred']
    def works(cid,sid):return rows.get((cid,sid),{}).get('eligible',False)
    def rank(c):
        cid=c['id']
        req=sum(works(cid,s['id']) for s in required)
        pref=sum(s['weight'] for s in preferred if works(cid,s['id']))
        latencies=[rows[cid,s['id']].get('latency_ms',1e8) for s in active if works(cid,s['id'])]
        latency=statistics.median(latencies) if latencies else 1e8
        return (-req,-pref,latency,cid)
    ranked=sorted(candidates,key=rank)
    complete=[c for c in ranked if all(works(c['id'],s['id']) for s in required)]
    if pinned_provider:
        pinned=[c for c in complete if c['provider_id']==pinned_provider]
        if pinned:complete=pinned+[c for c in complete if c not in pinned]
    primary=(complete or ranked)[0] if ranked else None
    primary_coverage={s['id'] for s in active if primary and works(primary['id'],s['id'])}
    backup=next((c for c in complete if primary and c['id']!=primary['id'] and all(works(c['id'],s) for s in primary_coverage)),None)
    old_routes={r['service']:r for r in (previous or {}).get('routes',[])}
    routes=[];missing=[]
    for service in active:
        options=[c for c in ranked if works(c['id'],service['id'])]
        old=old_routes.get(service['id'],{}).get('candidate')
        # Preserve a healthy active route even if another candidate became marginally faster.
        if old:options.sort(key=lambda c:c['id']!=old)
        elif primary:options.sort(key=lambda c:c['id']!=primary['id'])
        if not options:
            if service['mode']=='required':missing.append(service['id'])
            routes.append({'service':service['id'],'domains':service['routes'],'mode':service['mode'],'status':'UNAVAILABLE','candidate':None,'backups':[]})
            continue
        main=options[0]
        reserves=sorted(options[1:],key=lambda c:c['provider_id']==main['provider_id'])[:3]
        row=rows[main['id'],service['id']]
        routes.append({'service':service['id'],'domains':service['routes'],'mode':service['mode'],
            'status':row['status'],'evidence':row['evidence'],'candidate':main['id'],'provider_id':main['provider_id'],
            'upstream':main['upstream'],'backups':[{'candidate':c['id'],'provider_id':c['provider_id'],'upstream':c['upstream']} for c in reserves],
            'tested_domain':service['domain'],'sampled_addresses':row['dns'].get('addresses',[]),'partial_address_coverage':row.get('partial_address_coverage',False)})
    return {'schema_version':1,'checked_at':report['checked_at'],'applicable':not missing,'missing_required':missing,
            'primary':primary['id'] if primary else None,'backup':backup['id'] if backup else None,
            'ranking':[{'candidate':c['id'],'required_ok':-rank(c)[0],'preferred_score':-rank(c)[1]} for c in ranked],
            'routes':routes,'non_routing_errors':sorted({r['status'] for r in report['results'] if r['status'] in NON_ROUTING})}


class Stability:
    def __init__(self,failures=2,hold_seconds=300):
        self.failures=failures;self.hold_seconds=hold_seconds;self.counts={};self.switched={}
    def approve(self,proposed,current,now=None):
        now=time.time() if now is None else now
        if not proposed['applicable']:return False,'required-service-unavailable'
        if not current:return True,'initial-plan'
        previous={r['service']:r.get('candidate') for r in current['routes']}
        changed=[]; reasons=[]
        for route in proposed['routes']:
            sid=route['service']
            if route['candidate']==previous.get(sid):self.counts.pop(sid,None);continue
            changed.append(sid)
            self.counts[sid]=self.counts.get(sid,0)+1
            if self.counts[sid]<self.failures:reasons.append('awaiting-consecutive-service-failures')
            if now-self.switched.get(sid,float('-inf'))<self.hold_seconds:reasons.append('switch-cooldown')
        if reasons:return False,reasons[0]
        for sid in changed:self.switched[sid]=now;self.counts.pop(sid,None)
        return True,'service-plan-confirmed'
