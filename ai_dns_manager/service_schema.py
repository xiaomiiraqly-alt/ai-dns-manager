"""Local service definitions: remote provider feeds may never define credential probes."""
import copy
import ipaddress
import json
import re
from urllib.parse import urlsplit
from . import wire

MODES = {'required', 'preferred', 'off'}
LEVELS = {'endpoint': 1, 'http': 2, 'authenticated': 3, 'generation': 4}
ADAPTERS = {'openai', 'anthropic', 'json'}


def domain(value):
    if not isinstance(value, str):
        raise ValueError('Domain must be a string')
    value = value.lower().rstrip('.').encode('idna').decode('ascii')
    if len(value) > 253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')):
        raise ValueError('Invalid public DNS hostname')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('Use a DNS hostname, not an IP literal')
    if value.endswith(('.local', '.localhost', '.internal')):
        raise ValueError('Private service hostname is not allowed')
    wire.make_query(value)
    return value


def path(value):
    if not isinstance(value, str) or not value.startswith('/') or value.startswith('//') or len(value)>2048 or any(ord(c)<32 for c in value):
        raise ValueError('Expected a relative HTTP path')
    u=urlsplit(value)
    if u.scheme or u.netloc or u.fragment:
        raise ValueError('Invalid HTTP probe path')
    return value


def env_name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,99}',value):
        raise ValueError('Credentials must reference an environment variable, not a literal secret')
    return value


def validate_service(item):
    s=copy.deepcopy(item)
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,47}',s.get('id','')):
        raise ValueError('Invalid service id')
    s['name']=s.get('name',s['id'])
    if not isinstance(s['name'],str) or len(s['name'])>120 or any(ord(c)<32 for c in s['name']):
        raise ValueError('Invalid service name')
    s['domain']=domain(s['domain'])
    s['kind']=s.get('kind','web')
    if s['kind'] not in ('web','api'):
        raise ValueError('Service kind must be web or api')
    s['mode']=s.get('mode','preferred')
    if s['mode'] not in MODES:
        raise ValueError('Use required, preferred, or off')
    s['minimum_evidence']=s.get('minimum_evidence','http' if s['kind']=='web' else 'endpoint')
    if s['minimum_evidence'] not in LEVELS:
        raise ValueError('Invalid minimum evidence')
    weight=s.get('weight',1)
    if isinstance(weight,bool) or not isinstance(weight,int) or not 1<=weight<=1000:
        raise ValueError('Weight must be 1..1000')
    s['weight']=weight
    s['path']=path(s.get('path','/'))
    s['method']=s.get('method','GET')
    if s['method'] not in ('GET','POST'):raise ValueError('Probe method must be GET or POST')
    if 'body' in s and len(json.dumps(s['body']))>16384:raise ValueError('Probe body is too large')
    s['routes']=[domain(d) for d in s.get('routes',[s['domain']])]
    if s['domain'] not in s['routes'] or len(s['routes'])>16 or len(set(s['routes']))!=len(s['routes']):
        raise ValueError('Routes must contain the checked hostname, without duplicates')
    # Additional namespaces are explicit operator declarations, not claimed tested endpoints.
    for key in ('block_markers','auth_markers','content_markers'):
        values=s.get(key,[])
        if not isinstance(values,list) or len(values)>32 or any(not isinstance(x,str) or not 1<=len(x)<=200 for x in values):
            raise ValueError('Invalid response marker list')
        s[key]=[x.lower() for x in values]
    auth=s.get('auth')
    if auth:
        if not isinstance(auth,dict) or auth.get('adapter') not in ADAPTERS:
            raise ValueError('Unknown authenticated probe adapter')
        env_name(auth['key_env'])
        if 'model_env' in auth:env_name(auth['model_env'])
        if auth['adapter']!='json' and 'model_env' not in auth:
            raise ValueError('Generation probe needs a model environment variable')
        auth['path']=path(auth['path'])
        auth['method']=auth.get('method','POST' if auth['adapter']!='json' else 'GET')
        if auth['method'] not in ('GET','POST'):
            raise ValueError('Only explicit GET/POST probes are allowed')
        if auth.get('host',s['domain'])!=s['domain']:
            raise ValueError('Credential probes may not change the service hostname')
        if auth['adapter']=='json':
            pointer=auth.get('success_pointer','')
            if not isinstance(pointer,str) or not pointer.startswith('/'):
                raise ValueError('JSON authenticated probe requires an explicit success pointer')
        headers=auth.get('headers',{})
        if not isinstance(headers,dict) or any(k.lower() not in ('anthropic-version',) for k in headers):
            raise ValueError('Only non-secret version headers are configurable')
        if set(auth)-{'adapter','key_env','model_env','path','method','host','success_pointer','headers','body','max_tokens','token_field','auth_header','auth_prefix'}:
            raise ValueError('Unknown auth settings')
        if auth.get('auth_header','Authorization').lower() not in ('authorization','x-api-key','xi-api-key','api-key'):
            raise ValueError('Unsupported credential header')
        prefix=auth.get('auth_prefix','Bearer ')
        if prefix not in ('','Bearer '):raise ValueError('Invalid authentication prefix')
        cap=auth.get('max_tokens',256)
        if not isinstance(cap,int) or isinstance(cap,bool) or not 1<=cap<=1024:raise ValueError('Invalid token budget')
        if auth.get('token_field','max_tokens') not in ('max_tokens','max_completion_tokens'):
            raise ValueError('Unknown token limit field')
    return s


def load_services(document, overrides=None):
    if document.get('schema_version')!=1 or not isinstance(document.get('services'),list) or not 1<=len(document['services'])<=128:
        raise ValueError('Invalid service catalogue')
    overrides=overrides or {}
    items=[]
    for entry in document['services']+overrides.get('custom_services',[]):
        entry=copy.deepcopy(entry)
        if entry.get('id') in overrides.get('modes',{}):entry['mode']=overrides['modes'][entry['id']]
        if entry.get('id') in overrides.get('minimum_evidence',{}):entry['minimum_evidence']=overrides['minimum_evidence'][entry['id']]
        items.append(validate_service(entry))
    ids=[s['id'] for s in items]
    if len(items)>128 or len(ids)!=len(set(ids)):raise ValueError('Duplicate or too many service IDs')
    for key in ('modes','minimum_evidence'):
        if set(overrides.get(key,{}))-set(ids):raise ValueError('Settings refer to an unknown service')
    owners={}
    for s in items:
        if s['mode']=='off':continue
        for route in s['routes']:
            if route in owners:raise ValueError('Two enabled services own the same route: '+route)
            owners[route]=s['id']
    return items
