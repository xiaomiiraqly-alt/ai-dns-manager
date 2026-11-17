"""Bounded verified HTTPS probes; no redirects with secrets and no response bodies in reports."""
import http.client
import ipaddress
import json
import os
import ssl
import threading
import time
from urllib.parse import urljoin,urlsplit
from .transports import PinnedHTTPS, remaining

REGION_MARKERS=('user location is not supported','unsupported_country','unsupported country','country is not supported','region is not supported','not available in your country','not available in your region')
AUTH_MARKERS=('invalid api key','invalid_api_key','api key not valid','api_key_invalid','authentication_error','missing bearer','missing api key','incorrect api key','invalid authentication','unauthorized')
CHALLENGE_MARKERS=('cf-chl-','challenge-platform','just a moment...','verify you are human','checking your browser')
NON_ROUTING={'AUTH_OR_PERMISSION','QUOTA_OR_RATE_LIMIT','MODEL_OR_CONFIGURATION','KEY_MISSING','PROBE_NOT_AUTHORIZED','BUDGET_EXHAUSTED'}


def json_pointer(obj,pointer):
    try:
        for part in pointer.split('/')[1:]:
            part=part.replace('~1','/').replace('~0','~')
            obj=obj[int(part)] if isinstance(obj,list) else obj[part]
        return obj
    except (KeyError,TypeError,IndexError,ValueError):return None


def interpret(status,raw,service,authenticated=False):
    text=raw.decode('utf-8','replace').lower()
    try:data=json.loads(raw)
    except (ValueError,UnicodeDecodeError):data=None
    root=data[0] if isinstance(data,list) and data else data
    err=root.get('error') if isinstance(root,dict) else None
    error_text=json.dumps(err,ensure_ascii=True).lower() if err is not None else text
    result={'status':'UNKNOWN_RESPONSE','evidence':0,'http_status':status,'generation_ok':False}
    def verdict(label,level=0,**kw):return dict(result,status=label,evidence=level,**kw)
    if status==451 or any(x in error_text for x in REGION_MARKERS+tuple(service.get('block_markers',[]))):
        return verdict('REGION_BLOCKED')
    if any(x in text for x in CHALLENGE_MARKERS):return verdict('BOT_CHALLENGE')
    if status==429 or status==402:return verdict('QUOTA_OR_RATE_LIMIT')
    if status>=500:return verdict('SERVICE_ERROR')
    if authenticated:
        if status in (401,403) or any(x in error_text for x in AUTH_MARKERS):return verdict('AUTH_OR_PERMISSION')
        if status in (400,404,422):return verdict('MODEL_OR_CONFIGURATION')
        if status!=200 or err is not None:return verdict('REQUEST_REJECTED')
        adapter=service['auth']['adapter']
        if adapter=='openai':value=json_pointer(data,'/choices/0/message/content')
        elif adapter=='anthropic':
            value=''.join(x.get('text','') for x in (data or {}).get('content',[]) if isinstance(x,dict) and x.get('type')=='text') if isinstance(data,dict) else ''
        else:value=json_pointer(data,service['auth']['success_pointer'])
        if adapter!='json':
            return verdict('GENERATION_OK',4,generation_ok=True) if isinstance(value,str) and value.strip() else verdict('EMPTY_GENERATION')
        return verdict('AUTHENTICATED_OK',3) if value not in (None,'',[],{}) else verdict('AUTHENTICATED_EMPTY')
    if service['kind']=='api':
        if status in (400,401,403) and isinstance(root,dict) and any(x in error_text for x in AUTH_MARKERS+tuple(service.get('auth_markers',[]))):
            return verdict('AUTH_GATE',1)
        if status==200 and isinstance(data,(dict,list)) and err is None:return verdict('PUBLIC_API_OK',2)
        return verdict('ACCESS_DENIED' if status in (401,403) else 'REQUEST_REJECTED')
    if 200<=status<300 and raw:
        if service.get('content_markers') and not any(x in text for x in service['content_markers']):return verdict('CONTENT_MISMATCH')
        return verdict('HTTP_OK',2)
    return verdict('ACCESS_DENIED' if status in (401,403) else 'HTTP_ERROR')


def https_request(host,ip,path,method='GET',headers=None,body=None,timeout=8,max_bytes=262144):
    if not ipaddress.ip_address(ip).is_global:raise ValueError('Non-public probe destination')
    deadline=time.monotonic()+timeout
    connection=PinnedHTTPS(host,ip,443,timeout)
    try:
        # Explicitly connect first: an invalid certificate fails BEFORE HTTP headers/keys are sent.
        connection.connect()
        sock=connection.sock
        remote=sock.getpeername()[0]
        if ipaddress.ip_address(remote)!=ipaddress.ip_address(ip):raise ValueError('Unexpected peer address')
        sock.settimeout(remaining(deadline))
        connection.request(method,path,body=body,headers={'User-Agent':'ai-dns-manager/0.4','Accept-Encoding':'identity','Connection':'close',**(headers or {})})
        sock.settimeout(remaining(deadline))
        response=connection.getresponse()
        chunks=bytearray()
        while len(chunks)<=max_bytes and not response.isclosed():
            sock.settimeout(remaining(deadline))
            chunk=response.read1(min(8192,max_bytes+1-len(chunks)))
            if not chunk:break
            chunks.extend(chunk)
        if len(chunks)>max_bytes:raise ValueError('Response exceeds probe budget')
        return response.status,bytes(chunks),response.getheader('Location',''),remote
    finally:connection.close()


class ApiBudget:
    def __init__(self,maximum=0):
        self.remaining=maximum;self.lock=threading.Lock()
    def take(self):
        with self.lock:
            if self.remaining<=0:return False
            self.remaining-=1;return True


def probe_http(service,ip,timeout=8,authenticated=False,authorized=(),budget=None,environment=None,requester=https_request):
    env=os.environ if environment is None else environment
    started=time.monotonic()
    result={'status':'NOT_TESTED','evidence':0,'remote_ip':ip,'tls_valid':False,'generation_ok':False}
    try:
        method,headers,body,path=service.get('method','GET'),{},None,service['path']
        if method=='POST':body=json.dumps(service.get('body',{})).encode();headers['Content-Type']='application/json'
        if not ipaddress.ip_address(ip).is_global:return dict(result,status='UNSAFE_ADDRESS')
        if authenticated:
            if service['id'] not in authorized or not service.get('auth'):return dict(result,status='PROBE_NOT_AUTHORIZED')
            auth=service['auth'];key=env.get(auth['key_env'],'')
            model=env.get(auth.get('model_env',''),'')
            if not key or (auth['adapter']!='json' and not model):return dict(result,status='KEY_MISSING')
            if any(c in key+model for c in '\r\n') or len(key)>4096 or len(model)>200:return dict(result,status='MODEL_OR_CONFIGURATION')
            if budget is None or not budget.take():return dict(result,status='BUDGET_EXHAUSTED')
            method,path=auth['method'],auth['path']
            header=auth.get('auth_header','x-api-key' if auth['adapter']=='anthropic' else 'Authorization')
            prefix=auth.get('auth_prefix','' if auth['adapter']=='anthropic' else 'Bearer ')
            headers={**auth.get('headers',{}),header:prefix+key}
            if auth['adapter'] in ('openai','anthropic'):
                payload={'model':model,'messages':[{'role':'user','content':'Reply with the single word OK.'}],auth.get('token_field','max_tokens'):auth.get('max_tokens',256)}
                body=json.dumps(payload).encode()
            elif method=='POST':body=json.dumps(auth.get('body',{})).encode()
            if body is not None:headers['Content-Type']='application/json'
        elif service['kind']=='api':
            # Deliberately invalid, non-secret credential exercises the normal API gate.
            if service['id']=='gemini-api':headers['x-goog-api-key']='ai-dns-manager-invalid-key'
            elif service['id']=='anthropic-api':headers={'x-api-key':'ai-dns-manager-invalid-key','anthropic-version':'2023-06-01'}
            else:
                descriptor=service.get('auth',{})
                header=descriptor.get('auth_header','Authorization')
                prefix=descriptor.get('auth_prefix','Bearer ')
                headers[header]=prefix+'ai-dns-manager-invalid-key'
        for redirect in range(4):
            left=timeout-(time.monotonic()-started)
            if left<=0:raise TimeoutError()
            status,raw,location,remote=requester(service['domain'],ip,path,method,headers,body,left)
            result.update(tls_valid=True,remote_ip=remote)
            if status in (301,302,303,307,308):
                if authenticated:return dict(result,status='AUTH_REDIRECT_REFUSED',http_status=status)
                new=urlsplit(urljoin('https://'+service['domain']+path,location))
                if new.scheme!='https' or new.hostname!=service['domain'] or new.username or new.password or new.port not in (None,443):
                    return dict(result,status='CROSS_HOST_REDIRECT',http_status=status)
                path=new.path or '/'
                if new.query:path+='?'+new.query
                continue
            result.update(interpret(status,raw,service,authenticated))
            break
        else:result['status']='REDIRECT_LOOP'
    except ssl.SSLError:result['status']='TLS_ERROR'
    except OSError:
        # OSError covers connection failures; exact exception text may contain secrets and is never logged.
        result['status']='NETWORK_ERROR'
    except (ValueError,http.client.HTTPException,TypeError):result['status']='INVALID_RESPONSE'
    result['latency_ms']=round((time.monotonic()-started)*1000,1)
    return result
