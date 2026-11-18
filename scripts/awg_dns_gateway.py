#!/usr/bin/env python3
"""Expose the private AI DNS service ONLY on the AmneziaWG tunnel address.

One-step egress VPS bridge: it does not modify WireGuard configs, routes,
iptables/nftables, the host resolver, or any individual client settings.
The gateway runs in the existing AWG container's network namespace and
forwards its private DNS port 53 to the AI DNS manager on a Docker bridge.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
GATEWAY='ai-dns-awg-gateway'
OWNER_LABEL='io.github.xiaomiiraqly-alt.ai-dns-awg-gateway'
MANAGER_LABEL='io.github.xiaomiiraqly-alt.ai-dns-manager'


def command(*args, check=True):
    return subprocess.run(['docker',*args],capture_output=True,text=True,
                          check=check,timeout=30)


def inspect(name):
    result=command('inspect',name,check=False)
    if result.returncode:
        return None
    return json.loads(result.stdout)[0]


def require_label(info,label,name):
    if info and (info.get('Config',{}).get('Labels') or {}).get(label)!='true':
        raise ValueError('Refusing to manage unmanaged container: '+name)


def awg_address(container, interface):
    result=command('exec',container,'ip','-o','-4','addr','show','dev',interface)
    match=re.search(r'\binet\s+([0-9.]+/[0-9]+)\b',result.stdout)
    if not match:
        raise ValueError('AWG IPv4 address not found on '+interface)
    address=ipaddress.IPv4Interface(match.group(1))
    if address.ip.is_global or address.ip.is_loopback:
        raise ValueError('Refusing to expose DNS on non-private AWG address')
    return address


def active_generation(state):
    """Fail closed if Gemini was only validated at an authentication gate."""
    p=state/'active-plan.json'
    if not p.is_file():
        raise ValueError('No applied service-aware plan; Gemini must first pass real generation')
    data=json.loads(p.read_text())
    routes=[r for r in data.get('routes',[]) if r.get('service')=='gemini-api']
    if not data.get('applicable') or len(routes)!=1:
        raise ValueError('No valid mandatory Gemini route')
    route=routes[0]
    if route.get('status')!='GENERATION_OK' or route.get('evidence')!=4:
        raise ValueError('Mandatory Gemini has no verified generation route')
    # A plan can remain selected while unrelated preferred services change.
    # Only a fresh successful recheck of THIS required route renews proof.
    when=route.get('last_verified_at',data.get('checked_at'))
    if isinstance(when,bool) or not isinstance(when,(int,float)) or not 0<=time.time()-when<=1800:
        raise ValueError('Gemini generation proof expired')
    return route['provider_id']


def await_active_generation(state, seconds=0, interval=3):
    """Wait for a new generation-verified plan; never weaken the proof gate."""
    if isinstance(seconds,bool) or not isinstance(seconds,(int,float)) or not 0<=seconds<=600:
        raise ValueError('Invalid generation wait limit')
    deadline=time.monotonic()+seconds
    last=None
    while True:
        try:
            return active_generation(state)
        except ValueError as exc:
            last=exc
            # Invalid or unverified routes must not be treated as usable;
            # waiting is only useful while scans are generating a new plan.
            if time.monotonic()>=deadline:
                raise
            if str(exc) not in ('Gemini generation proof expired',
                                'No applied service-aware plan; Gemini must first pass real generation'):
                raise
            time.sleep(min(interval,max(0,deadline-time.monotonic())))


def config_for(manager_ip, awg):
    return {'timeout_seconds':3,'request_timeout_seconds':8,
            'cooldown_seconds':10,'failure_threshold':2,
            'health_interval_seconds':0,'max_workers':32,
            'allowed_clients':[str(awg.network),'127.0.0.0/8'],
            'default_group':'manager',
            'groups':{'manager':[{'name':'private-ai-dns-manager',
                                  'protocol':'udp','ip':manager_ip,'port':5353}]},
            'rules':[]}


def write_config(contents):
    target=ROOT/'local'/'awg-gateway'
    target.mkdir(mode=0o700,parents=True,exist_ok=True)
    p=target/('router-'+str(time.time_ns())+'.json')
    p.write_text(json.dumps(contents,indent=2)+'\n')
    p.chmod(0o644)  # Contains only private network metadata, no API keys.
    return p


def ensure_manager_network(manager, network):
    current=inspect(manager)
    if not current:
        raise ValueError('AI DNS Manager container not found')
    require_label(current,MANAGER_LABEL,manager)
    if not current['State']['Running']:
        raise ValueError('AI DNS Manager must be running before AWG integration')
    networks=current['NetworkSettings']['Networks'] or {}
    if network not in networks:
        # Preserve the manager's current Internet egress route when adding
        # a second private bridge; Docker chooses default gateway by priority.
        command('network','connect','--gw-priority','-1',network,manager)
        current=inspect(manager)
    address=current['NetworkSettings']['Networks'].get(network,{}).get('IPAddress')
    if not address or not ipaddress.ip_address(address).is_private:
        raise ValueError('No private shared Docker network address for manager')
    return address


def provision(manager, awg_container, network, interface, wait_seconds=0):
    current=inspect(GATEWAY)
    require_label(current,OWNER_LABEL,GATEWAY)
    awg=inspect(awg_container)
    if not awg or not awg['State']['Running']:
        raise ValueError('Existing AWG container is not running')
    if network not in (awg.get('NetworkSettings',{}).get('Networks') or {}):
        raise ValueError('AWG is not connected to the expected private Docker network')
    address=awg_address(awg_container,interface)
    provider=await_active_generation(ROOT/'local'/'service-state',seconds=wait_seconds)
    manager_ip=ensure_manager_network(manager,network)
    if current and current['State']['Running']:
        # Detect stale forwarding after main manager container replacement.
        mounts=current.get('Mounts') or []
        source=next((m.get('Source') for m in mounts
                     if m.get('Destination')=='/app/config/awg-gateway.json'),None)
        if not source:
            raise ValueError('Existing gateway has no owned forwarding configuration')
        try:
            old=json.loads(Path(source).read_text())
            old_ip=old['groups']['manager'][0]['ip']
        except (OSError,ValueError,KeyError,IndexError,TypeError) as exc:
            raise ValueError('Cannot validate current gateway forwarding') from exc
        if old_ip!=manager_ip:
            raise ValueError('Gateway target changed after manager upgrade: run uninstall then install')
        print('Gateway is already running; no changes made.')
        print('VPN DNS address:',str(address.ip))
        print('Verified Gemini provider:',provider)
        return
    if current:
        raise ValueError('Stopped gateway exists; inspect it before replacement')
    cfg=write_config(config_for(manager_ip,address))
    manager_info=inspect(manager)
    image=manager_info['Config']['Image']
    mount='type=bind,source='+str(cfg)+',target=/app/config/awg-gateway.json,readonly'
    try:
        result=command('run','-d','--name',GATEWAY,
              '--label',OWNER_LABEL+'=true',
              '--restart','unless-stopped',
              '--network','container:'+awg_container,
              '--read-only','--user','0:0',
              '--cap-drop','ALL','--cap-add','NET_BIND_SERVICE',
              '--security-opt','no-new-privileges',
              '--memory','96m','--pids-limit','96',
              '--log-driver','json-file','--log-opt','max-size=5m',
              '--log-opt','max-file=3',
              '--mount',mount,
              '--health-cmd','python -m ai_dns_manager.healthcheck --host '+str(address.ip)+' --port 53',
              '--health-interval','15s','--health-timeout','4s',
              '--health-retries','3',
              '--entrypoint','python',image,
              '-m','ai_dns_manager.server','--config','/app/config/awg-gateway.json',
              '--listen',str(address.ip),'--port','53')
        print('Gateway container:',result.stdout.strip()[:12])
        for _ in range(15):
            ok=command('exec',GATEWAY,'python','-m','ai_dns_manager.healthcheck',
                       '--host',str(address.ip),'--port','53',check=False)
            if ok.returncode==0:
                print('PRIVATE DNS READY at',str(address.ip)+':53 (UDP/TCP)')
                print('Selected Gemini provider:',provider)
                print('VPN clients must set their tunnel DNS to',str(address.ip))
                print('No host DNS, firewall, AWG config or client was changed.')
                return
            time.sleep(1)
        raise RuntimeError('AWG gateway failed to serve private DNS')
    except BaseException:
        info=inspect(GATEWAY)
        if info:
            require_label(info,OWNER_LABEL,GATEWAY)
            command('rm','-f',GATEWAY,check=False)
        raise


def remove():
    info=inspect(GATEWAY)
    require_label(info,OWNER_LABEL,GATEWAY)
    if info:
        command('rm','-f',GATEWAY)
    print('Private AWG DNS gateway removed; AWG and main DNS manager left running.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',nargs='?',choices=['install','status','uninstall'],default='install')
    p.add_argument('--manager',default='ai-dns-manager')
    p.add_argument('--awg',default='amnezia-awg2')
    p.add_argument('--network',default='amnezia-dns-net')
    p.add_argument('--interface',default='awg0')
    p.add_argument('--wait-seconds',type=int,default=240,
                   help='Wait for the next real Gemini generation proof, without bypassing it (0..600)')
    a=p.parse_args()
    if not all(re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}',v)
               for v in (a.manager,a.awg,a.network,a.interface)):
        p.error('Invalid container, network or interface name')
    try:
        if a.action=='install':
            provision(a.manager,a.awg,a.network,a.interface,a.wait_seconds)
        elif a.action=='status':
            info=inspect(GATEWAY)
            require_label(info,OWNER_LABEL,GATEWAY)
            print(json.dumps({'installed':bool(info),'running':bool(info and info['State']['Running']),
                              'health':(info or {}).get('State',{}).get('Health',{}).get('Status')},
                             indent=2))
        else:
            remove()
    except (OSError,ValueError,RuntimeError,KeyError,subprocess.CalledProcessError) as exc:
        p.exit(1,type(exc).__name__+': '+str(exc)+'\n')


if __name__=='__main__':
    main()
