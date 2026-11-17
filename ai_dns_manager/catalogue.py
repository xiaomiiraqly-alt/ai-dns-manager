"""Provider data updates with validated stale-cache fallback; never downloads executable code."""
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from . import wire
from .service_schema import domain
from .transports import Upstream,exchange,PinnedHTTPS,remaining

MAX_BYTES=1048576
MAX_PROVIDERS=256


def atomic_json(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,tmp=tempfile.mkstemp(prefix='.aidns-',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as f:
            json.dump(data,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def public_ip(value):
    ip=ipaddress.ip_address(value)
    if not ip.is_global or ip.is_multicast or ip.is_unspecified or getattr(ip,'ipv4_mapped',None):raise ValueError('Non-public address')
    return str(ip)


def doh_url(value):
    value=value.removesuffix('{?dns}')
    u=urlsplit(value)
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.port not in (None,443):
        raise ValueError('Invalid public DoH URL')
    domain(u.hostname)
    if not u.path.startswith('/') or any(ord(c)<=32 for c in value):raise ValueError('Invalid DoH path')
    return value


def normalize_provider(row,source):
    pid=row.get('id','')
    if pid=='reference' or not isinstance(pid,str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}',pid):raise ValueError('Invalid provider id')
    name=row.get('name',pid)
    if not isinstance(name,str) or len(name)>100 or any(ord(c)<32 for c in name):raise ValueError('Invalid provider name')
    result={'id':pid,'name':name,'sources':[source]}
    for field,check in [('ipv4',public_ip),('hosts',domain),('doh',doh_url),('dot',domain)]:
        values=row.get(field,[])
        if not isinstance(values,list) or len(values)>64:raise ValueError('Invalid provider array')
        result[field]=[]
        for val in values:
            try:
                normalized=check(val)
                if normalized not in result[field]:result[field].append(normalized)
            except (ValueError,TypeError,AttributeError):continue
    if not result['ipv4'] and not result['hosts'] and not result['doh'] and not result['dot']:raise ValueError('Provider has no public endpoints')
    return result


def parse_feed(raw,format,source):
    if len(raw)>MAX_BYTES:raise ValueError('Provider feed exceeds size limit')
    text=raw.decode('utf-8-sig')
    rows=[];retired=[]
    if format=='aidns-v1':
        doc=json.loads(text)
        if not isinstance(doc,dict) or doc.get('schemaVersion')!=1 or not isinstance(doc.get('providers'),list):raise ValueError('Unsupported provider schema')
        rows=doc['providers']
        for value in doc.get('retiredIpv4',[]):
            try:retired.append(public_ip(value))
            except (ValueError,TypeError):continue
    elif format=='dnsswitch':
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):continue
            parts=[x.strip() for x in line.split('|')]
            if len(parts)<4:continue
            pid='switch-'+re.sub('[^a-z0-9-]','',parts[0].lower())[:48]
            rows.append({'id':pid,'name':parts[1],'ipv4':re.split(r'[,;\s]+',parts[3]),'doh':[parts[4]] if len(parts)>4 and parts[4] else []})
    else:raise ValueError('Unsupported feed format')
    if len(rows)>MAX_PROVIDERS:raise ValueError('Provider feed contains too many entries')
    providers=[]
    for row in rows:
        try:providers.append(normalize_provider(row,source))
        except (ValueError,TypeError,AttributeError):continue
    if not providers:raise ValueError('Provider feed has no valid entries')
    return {'providers':providers,'retired':sorted(set(retired))}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def download(url,timeout=8):
    u=urlsplit(url)
    if u.scheme!='https' or u.hostname not in ('raw.githubusercontent.com','cdn.jsdelivr.net') or u.username or u.password or u.query or u.fragment or u.port not in (None,443):
        raise ValueError('Only explicitly configured GitHub/jsDelivr HTTPS provider feeds are allowed')
    deadline=time.monotonic()+timeout
    addresses=list(dict.fromkeys(public_ip(row[4][0]) for row in socket.getaddrinfo(u.hostname,443,type=socket.SOCK_STREAM)))
    if not addresses:raise OSError('No public source address')
    conn=PinnedHTTPS(u.hostname,addresses[0],443,remaining(deadline))
    try:
        conn.connect();sock=conn.sock
        conn.request('GET',u.path or '/',headers={'User-Agent':'ai-dns-manager/0.4','Accept-Encoding':'identity','Connection':'close'})
        sock.settimeout(remaining(deadline));response=conn.getresponse()
        if response.status!=200:raise ValueError('Provider feed HTTP error')
        body=bytearray()
        while len(body)<=MAX_BYTES and not response.isclosed():
            sock.settimeout(remaining(deadline))
            chunk=response.read1(min(8192,MAX_BYTES+1-len(body)))
            if not chunk:break
            body.extend(chunk)
        if len(body)>MAX_BYTES:raise ValueError('Provider feed exceeds size limit')
        return bytes(body)
    finally:conn.close()



def update_source(source,cache_dir,offline=False,force=False,fetcher=download,clock=time.time):
    identity=json.dumps({k:source[k] for k in ('id','format','urls')},sort_keys=True)
    digest=hashlib.sha256(identity.encode()).hexdigest()
    path=Path(cache_dir)/(digest+'.json')
    cached=None
    try:
        if path.stat().st_size>MAX_BYTES*2:raise ValueError('Oversized cache')
        item=json.loads(path.read_text())
        if item['source_digest']!=digest:raise ValueError('Cache source mismatch')
        # Re-parse saved raw text; a broken or empty feed never replaces a good snapshot.
        parsed=parse_feed(item['text'].encode(),source['format'],source['id'])
        cached=(item,parsed)
    except (OSError,ValueError,KeyError,TypeError):pass
    ttl=source.get('refresh_seconds',21600)
    if not isinstance(ttl,int) or not 300<=ttl<=604800:raise ValueError('Invalid provider update interval')
    fresh=cached and isinstance(cached[0].get('saved_at'),(int,float)) and 0<=clock()-cached[0]['saved_at']<ttl
    if offline or (fresh and not force):
        return {'source':source['id'],'origin':'cache' if fresh else 'stale-cache' if cached else 'unavailable',**(cached[1] if cached else {'providers':[],'retired':[]})}
    errors=[]
    for url in source['urls']:
        try:
            raw=fetcher(url)
            parsed=parse_feed(raw,source['format'],source['id'])
            atomic_json(path,{'source_digest':digest,'saved_at':clock(),'text':raw.decode('utf-8-sig')})
            return {'source':source['id'],'origin':'remote',**parsed}
        except (OSError,ValueError,UnicodeError,http.client.HTTPException) as exc:errors.append(type(exc).__name__)
    return {'source':source['id'],'origin':'stale-cache' if cached else 'unavailable','errors':errors,**(cached[1] if cached else {'providers':[],'retired':[]})}


def merge_catalogues(entries,excluded=(),retired=()):
    # Shared public endpoint or declared host joins records; retain source provenance.
    merged=[]
    for item in entries:
        if item['id'] in excluded:continue
        item=copy.deepcopy(item)
        item['ipv4']=[ip for ip in item['ipv4'] if ip not in retired]
        tokens=lambda row:set(row['ipv4']+row['hosts']+row['doh']+row.get('dot',[]))
        matches=[r for r in merged if r['id']==item['id'] or tokens(r)&tokens(item)]
        for match in matches:
            merged.remove(match)
            for field in ('ipv4','hosts','doh','dot','sources'):
                item[field]=list(dict.fromkeys(match.get(field,[])+item.get(field,[])))
            item['id']=match['id'];item['name']=match['name']
        merged.append(item)
    return merged


def endpoint_id(config):
    up=Upstream.parse(config)
    key=json.dumps([up.protocol,up.ip,up.port,up.hostname,up.path])
    return 'ep-'+hashlib.sha256(key.encode()).hexdigest()[:16]


def expand_providers(providers,baselines,discover=True,excluded_addresses=(),resolver=None):
    if resolver is None:
        def resolver(host):
            found=[]
            for baseline in baselines[:2]:
                try:found+=wire.a_records(exchange(wire.make_query(host),Upstream.parse(baseline),2))
                except (OSError,ValueError):continue
            return found
    result=[];seen=set()
    def add(config,pid,source):
        ip=public_ip(config.get('bootstrap_ip') or config.get('ip'))
        if ip in excluded_addresses:return
        identifier=endpoint_id(config)
        if identifier in seen:return
        seen.add(identifier);config['name']=identifier
        result.append({'id':identifier,'provider_id':pid,'sources':source,'upstream':config})
    for base in baselines:add(copy.deepcopy(base),'reference', ['local-baseline'])
    for provider in providers:
        hosts=list(dict.fromkeys(provider['hosts']+[urlsplit(u).hostname for u in provider['doh']]+provider.get('dot',[])))
        discovered={}
        if discover:
            for host in hosts[:8]:
                try:discovered[host]=list(dict.fromkeys(public_ip(ip) for ip in resolver(host)))[:8]
                except (ValueError,OSError):discovered[host]=[]
        ips=provider['ipv4'][:32]
        for ip in ips:add({'ip':ip,'protocol':'udp'},provider['id'],provider['sources'])
        for url in provider['doh'][:8]:
            # A current hostname answer is preferred; old bootstrap addresses remain diagnostic candidates.
            for ip in list(dict.fromkeys(discovered.get(urlsplit(url).hostname,[])+ips))[:32]:
                add({'protocol':'doh','bootstrap_ip':ip,'url':url},provider['id'],provider['sources'])
        for hostname in provider.get('dot',[])[:8]:
            for ip in list(dict.fromkeys(discovered.get(hostname,[])+ips))[:32]:
                add({'protocol':'dot','bootstrap_ip':ip,'hostname':hostname},provider['id'],provider['sources'])
        if len(result)>512:raise ValueError('More than 512 unique endpoints; narrow provider settings')
    return result


def build_catalogue(settings,cache_dir,bundled,offline=False,force=False,fetcher=download,resolver=None):
    sources=settings.get('sources',[])
    if not isinstance(sources,list) or len(sources)>8:raise ValueError('Too many provider sources')
    for source in sources:
        if not re.fullmatch(r'[a-z0-9-]{1,50}',source['id']) or not 1<=len(source['urls'])<=3:raise ValueError('Invalid provider source')
    with ThreadPoolExecutor(max_workers=4) as ex:
        remote=list(ex.map(lambda s:update_source(s,cache_dir,offline,force,fetcher),sources))
    seed=parse_feed(Path(bundled).read_bytes(),'aidns-v1','bundled')
    retired=set(seed['retired'])
    entries=list(seed['providers'])
    for doc in remote:retired.update(doc['retired']);entries+=doc['providers']
    for row in settings.get('custom_providers',[]):entries.append(normalize_provider(row,'local'))
    exclusions=settings.get('exclude_providers',[])
    # Exclude by endpoint too, so a duplicate source cannot re-enable an explicitly excluded provider.
    blocked=set(settings.get('exclude_addresses',[]))|retired
    for row in entries:
        if row['id'] in exclusions:blocked.update(row['ipv4'])
    merged=merge_catalogues(entries,exclusions,blocked)
    candidates=expand_providers(merged,settings['baselines'],settings.get('discover_addresses',True) and not offline,blocked,resolver)
    return {'providers':merged,'candidates':candidates,'sources':[{k:v for k,v in r.items() if k not in ('providers','retired')} for r in remote],
            'retired':sorted(retired),'updated_at':time.time()}
