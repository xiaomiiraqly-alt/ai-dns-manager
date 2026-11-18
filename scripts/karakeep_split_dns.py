#!/usr/bin/env python3
"""Private split DNS for running Karakeep containers sharing an AWG client.

No Compose recreation, host resolver change, VPN restart or firewall mutation.
A loopback-only sidecar in the existing AWG client network namespace routes
AI domains to the private egress DNS gateway and ordinary/Docker domains to
the exact previously configured DNS resolvers. Keeps byte-for-byte backups
of the target containers' Docker-managed resolv.conf files for rollback.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
SIDECAR='karakeep-ai-dns'
OWNER='io.github.xiaomiiraqly-alt.karakeep-ai-dns'
AWG='karakeep-awg-client'
TARGETS=('karakeep-web-1','karakeep-chrome-1')
LOCAL_DNS='127.0.0.53'
GATEWAY_DEFAULT='10.8.1.1'
STATE=ROOT/'local'/'karakeep-split-dns'


def command(*args,check=True,timeout=35):
    return subprocess.run(['docker',*args],capture_output=True,text=True,
                          check=check,timeout=timeout)


def inspect(name):
    result=command('inspect',name,check=False)
    return json.loads(result.stdout)[0] if result.returncode==0 else None


def owned(info):
    return info and (info.get('Config',{}).get('Labels') or {}).get(OWNER)=='true'


def atomic_json(path,data):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.dns-',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as stream:
            json.dump(data,stream,indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def nameservers(text):
    values=[]
    for line in text.splitlines():
        words=line.split('#',1)[0].split()
        if len(words)>=2 and words[0]=='nameserver':
            try:
                ip=str(ipaddress.ip_address(words[1]))
            except ValueError as exc:
                raise ValueError('Invalid existing DNS nameserver') from exc
            if ip not in values and ip!=LOCAL_DNS:
                values.append(ip)
    if not values:
        raise ValueError('Cannot preserve original DNS: no upstream nameservers')
    return values


def rewrite_resolv(original,local=LOCAL_DNS):
    """Preserve search/options and replace nameserver entries only."""
    if not nameservers(original):
        raise ValueError('No previous nameservers')
    result=[line for line in original.splitlines()
            if not re.match(r'^\s*nameserver\s+',line)]
    return 'nameserver '+local+'\n' + '\n'.join(result).strip('\n') + '\n'


def config_for(gateway,ordinary,profiles):
    ipaddress.IPv4Address(gateway)
    if not ipaddress.ip_address(gateway).is_private:
        raise ValueError('Private AWG gateway address required')
    std=[{'name':'existing-'+str(i),'protocol':'udp','ip':ip,'port':53}
         for i,ip in enumerate(ordinary)]
    remote={'name':'awg-private-dns','protocol':'udp','ip':gateway,'port':53}
    rules=[]
    for profile in profiles:
        if profile['mode']=='off':
            continue
        group='mandatory' if profile['mode']=='required' else 'preferred'
        for domain in profile['routes']:
            rules.append({'domain':domain,'group':group})
    return {'timeout_seconds':2.5,'request_timeout_seconds':7,
            'cooldown_seconds':10,'failure_threshold':2,
            'health_interval_seconds':0,'max_workers':32,
            'allowed_clients':['127.0.0.0/8'],
            'default_group':'standard',
            'groups':{'standard':std,
                      'mandatory':[remote],
                      'preferred':[remote]+std},
            'rules':rules}


def docker_root():
    result=command('info','--format','{{.DockerRootDir}}')
    return Path(result.stdout.strip()).resolve()


def target_files(awg_name=AWG,targets=TARGETS):
    awg=inspect(awg_name)
    if not awg or not awg['State']['Running']:
        raise ValueError('Karakeep AWG client must be running')
    awg_pid=awg['State']['Pid']
    awg_ns=os.stat('/proc/'+str(awg_pid)+'/ns/net').st_ino
    root=docker_root()/'containers'
    found={}
    for name in targets:
        info=inspect(name)
        if not info or not info['State']['Running']:
            raise ValueError('Karakeep container not running: '+name)
        ns=os.stat('/proc/'+str(info['State']['Pid'])+'/ns/net').st_ino
        if ns!=awg_ns:
            raise ValueError(name+' is not sharing the AWG client network namespace')
        path=Path(info['ResolvConfPath'])
        real=path.resolve()
        if path.is_symlink() or not real.is_relative_to(root) or not real.is_file():
            raise ValueError('Refusing unexpected Docker resolver file for '+name)
        if real not in found:
            found[real]={'containers':[], 'before':real.read_text()}
        found[real]['containers'].append({'name':name,'id':info['Id']})
    return found


def write_in_place(path,content):
    """Docker bind-mounts resolv.conf by inode; os.replace would not update it."""
    if not path.is_file() or path.is_symlink():
        raise ValueError('Resolver path changed during install')
    with path.open('r+',encoding='utf-8') as stream:
        stream.seek(0)
        stream.write(content)
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())


def run_gateway_check(container,gateway):
    """Prove that the AWG tunnel actually reaches the egress private DNS."""
    code=(
        'from ai_dns_manager import wire\n'
        'from ai_dns_manager.transports import Upstream,exchange\n'
        'q=wire.make_query("generativelanguage.googleapis.com")\n'
        'r=exchange(q,Upstream.parse({"ip":'+json.dumps(gateway)+',"port":53}),4)\n'
        'assert (wire.header(r)[1]&15)==0 and wire.a_records(r), "No verified Gemini DNS route"\n'
    )
    result=command('exec',container,'python','-c',code,check=False,timeout=15)
    if result.returncode:
        raise ValueError('AWG private DNS gateway is not ready for Gemini')


def run_local_check(container):
    code=(
        'from ai_dns_manager import wire\n'
        'from ai_dns_manager.transports import Upstream,exchange\n'
        'for name in ("generativelanguage.googleapis.com","example.com"):\n'
        ' q=wire.make_query(name)\n'
        ' r=exchange(q,Upstream.parse({"ip":"127.0.0.53","port":53}),5)\n'
        ' assert (wire.header(r)[1]&15)==0 and wire.a_records(r), name\n'
    )
    result=command('exec',container,'python','-c',code,check=False,timeout=20)
    if result.returncode:
        raise ValueError('Split DNS listener failed private AI or ordinary DNS check')


def start_sidecar(image,awg,config):
    mount='type=bind,source='+str(config)+',target=/app/config/karakeep-dns.json,readonly'
    run=command('run','-d','--name',SIDECAR,'--label',OWNER+'=true',
                '--network','container:'+awg,'--restart','unless-stopped',
                '--read-only','--user','0:0',
                '--cap-drop','ALL','--cap-add','NET_BIND_SERVICE',
                '--security-opt','no-new-privileges',
                '--memory','96m','--pids-limit','96',
                '--log-driver','json-file','--log-opt','max-size=5m',
                '--log-opt','max-file=3',
                '--mount',mount,
                '--health-cmd','python -m ai_dns_manager.healthcheck --host 127.0.0.53 --port 53',
                '--health-interval','20s','--health-timeout','5s',
                '--health-retries','3',
                '--entrypoint','python',image,
                '-m','ai_dns_manager.server',
                '--config','/app/config/karakeep-dns.json',
                '--listen',LOCAL_DNS,'--port','53')
    for _ in range(20):
        result=command('exec',SIDECAR,'python','-m','ai_dns_manager.healthcheck',
                       '--host',LOCAL_DNS,'--port','53',check=False)
        if result.returncode==0:
            return
        time.sleep(.5)
    raise RuntimeError('Split DNS sidecar never became healthy')


def provision(gateway,awg,targets):
    if STATE.joinpath('manifest.json').exists():
        raise ValueError('Split DNS is already installed; use status or uninstall')
    if inspect(SIDECAR):
        raise ValueError('Sidecar already exists; inspect it before changing DNS')
    files=target_files(awg,targets)
    all_original=[]
    for item in files.values():
        all_original+=nameservers(item['before'])
    original=list(dict.fromkeys(all_original))
    from ai_dns_manager.service_schema import load_services
    profiles=load_services(json.loads((ROOT/'config'/'services.json').read_text()))
    cfg=config_for(gateway,original,profiles)
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    cfg_path=STATE/'router.json'
    cfg_path.write_text(json.dumps(cfg,indent=2)+'\n')
    cfg_path.chmod(0o644)
    revision=command('version','--format','{{.Server.Version}}',check=False)
    _=revision  # Keep Docker-version probing non-mutating.
    image='ai-dns-manager-karakeep:local'
    command('build','-t',image,str(ROOT),timeout=250)
    command('run','--rm','--network','none','--read-only','--cap-drop','ALL',
            '--mount','type=bind,source='+str(cfg_path)+',target=/app/config/karakeep-dns.json,readonly',
            '--entrypoint','python',image,'-m','ai_dns_manager.server',
            '--config','/app/config/karakeep-dns.json','--check-config',timeout=25)
    manifest={'schema_version':1,'timestamp':datetime.now(timezone.utc).isoformat(),
              'gateway':gateway,'sidecar':SIDECAR,'resolvers':[]}
    for path,item in files.items():
        manifest['resolvers'].append({'path':str(path),
            'containers':item['containers'],
            'original':item['before'],
            'applied':rewrite_resolv(item['before'])})
    started=False
    changed=[]
    try:
        start_sidecar(image,awg,cfg_path)
        started=True
        run_gateway_check(SIDECAR,gateway)
        run_local_check(SIDECAR)
        # Commit recovery metadata BEFORE the first resolver mutation.
        atomic_json(STATE/'manifest.json',manifest)
        for row in manifest['resolvers']:
            path=Path(row['path'])
            if path.read_text()!=row['original']:
                raise RuntimeError('Docker resolver changed since preflight; refusing unsafe overwrite')
            write_in_place(path,row['applied'])
            changed.append(row)
        print('KARAKEEP SPLIT DNS ACTIVE')
        print('AI domains: private AWG DNS '+gateway+':53')
        print('Ordinary and Docker domains: previous resolver(s) '+', '.join(original))
        print('Web and Chrome: switched without container restart or Compose edits')
        print('Rollback: python3 scripts/karakeep_split_dns.py uninstall')
    except BaseException:
        for row in reversed(changed):
            try:
                write_in_place(Path(row['path']),row['original'])
            except OSError:
                print('WARNING: failed to restore '+row['path'],file=sys.stderr)
        (STATE/'manifest.json').unlink(missing_ok=True)
        if started and owned(inspect(SIDECAR)):
            command('rm','-f',SIDECAR,check=False)
        raise


def remove():
    manifest_path=STATE/'manifest.json'
    if not manifest_path.is_file():
        if owned(inspect(SIDECAR)):
            raise ValueError('Sidecar exists without manifest; refusing unsafe removal')
        print('No managed Karakeep DNS changes found')
        return
    data=json.loads(manifest_path.read_text())
    if data.get('schema_version')!=1:
        raise ValueError('Unsupported resolver recovery format')
    # Preflight all paths and identities so uninstall cannot strand the other
    # container at the removed local DNS endpoint.
    current={}
    for row in data['resolvers']:
        p=Path(row['path'])
        if p.is_symlink() or not p.is_file():
            raise ValueError('Resolver was replaced; cannot safely restore '+str(p))
        if p.read_text()!=row['applied']:
            raise ValueError('Resolver changed since install; refusing to overwrite '+str(p))
        for target in row['containers']:
            info=inspect(target['name'])
            if not info or info['Id']!=target['id']:
                raise ValueError('Container recreated since install; resolver restoration requires review: '+target['name'])
        current[p]=row['original']
    for path,original in current.items():
        write_in_place(path,original)
    sidecar=inspect(SIDECAR)
    if sidecar and not owned(sidecar):
        raise ValueError('Refusing to remove unmanaged DNS container')
    if sidecar:
        command('rm','-f',SIDECAR)
    manifest_path.unlink()
    print('KARAKEEP DNS RESTORED; VPN and Compose unchanged')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['install','status','uninstall'],nargs='?',default='install')
    p.add_argument('--gateway',default=GATEWAY_DEFAULT,
                   help='Private AWG server DNS address (must already serve UDP/TCP 53)')
    p.add_argument('--awg',default=AWG)
    p.add_argument('--web',default=TARGETS[0])
    p.add_argument('--chrome',default=TARGETS[1])
    args=p.parse_args()
    try:
        ip=ipaddress.IPv4Address(args.gateway)
        if not ip.is_private:
            raise ValueError('Public DNS gateways not allowed')
        if not all(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}',v)
                   for v in (args.awg,args.web,args.chrome)):
            raise ValueError('Invalid Docker container name')
        if args.action=='install':
            provision(str(ip),args.awg,(args.web,args.chrome))
        elif args.action=='uninstall':
            remove()
        else:
            sidecar=inspect(SIDECAR)
            p=STATE/'manifest.json'
            print(json.dumps({'installed':p.is_file(),
                              'running':bool(sidecar and sidecar['State']['Running']),
                              'health':(sidecar or {}).get('State',{}).get('Health',{}).get('Status'),
                              'gateway':str(ip),
                              'note':'Changes to Docker-managed resolv.conf are runtime-only and can be reset by container recreation.'},indent=2))
    except (OSError,ValueError,RuntimeError,KeyError,TypeError,
            subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        p.exit(1,type(exc).__name__+': '+str(exc)+'\n')


if __name__=='__main__':
    main()
