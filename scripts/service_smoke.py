"""Docker service-aware startup check with networking disabled and a tiny offline fixture."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from install import docker,inspect

image=sys.argv[1] if len(sys.argv)>1 else 'ai-dns-manager:test'
name='aidns-service-smoke-'+str(os.getpid())
with tempfile.TemporaryDirectory() as tmp:
    config=json.loads(Path('config/manager.json').read_text())
    config['providers']['sources']=[]
    config['providers']['discover_addresses']=False
    config['round_budget_seconds']=1
    ids=[s['id'] for s in json.loads(Path('config/services.json').read_text())['services']]
    config['service_overrides']['modes']={sid:('required' if sid=='gemini-api' else 'off') for sid in ids}
    f=Path(tmp)/'manager.json';f.write_text(json.dumps(config));f.chmod(0o644)
    try:
        docker('run','-d','--name',name,'--network','none','--read-only','--cap-drop','ALL',
               '--security-opt','no-new-privileges','--tmpfs','/state:rw,noexec,nosuid,mode=1777',
               '--mount',f'type=bind,source={f},target=/app/config/manager.json,readonly',
               '--entrypoint','python',image,'-m','ai_dns_manager.manager','serve','--state-dir','/state',
               '--offline','--listen','127.0.0.1','--port','5353')
        for _ in range(20):
            r=subprocess.run(['docker','exec',name,'python','-m','ai_dns_manager.healthcheck'],capture_output=True)
            if r.returncode==0:break
            time.sleep(.2)
        else:raise RuntimeError('Service-aware listener did not start')
        docker('stop','--time','15',name)
        if inspect(name)['State']['ExitCode']!=0:raise RuntimeError('Service manager did not stop gracefully')
        print('Service-aware non-root/read-only UDP/TCP and SIGTERM check passed')
    finally:
        subprocess.run(['docker','rm','-f',name],capture_output=True)
