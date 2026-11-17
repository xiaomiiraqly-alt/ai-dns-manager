"""CI runtime check: non-root, read-only, no external network, clean termination."""
from pathlib import Path
import os
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from install import docker, inspect, LABEL

image = sys.argv[1] if len(sys.argv) > 1 else 'ai-dns-manager:test'
name = 'ai-dns-smoke-' + str(os.getpid())
try:
    docker('run','-d','--name',name,'--label',LABEL+'=true','--network','none',
           '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
           '--entrypoint','python',image,'-m','ai_dns_manager.server','--listen','127.0.0.1','--port','5353')
    for attempt in range(20):
        result=subprocess.run(['docker','exec',name,'python','-m','ai_dns_manager.healthcheck'])
        if result.returncode == 0:
            break
        time.sleep(.5)
    else:
        raise RuntimeError('Container UDP/TCP listeners failed')
    docker('stop','--time','5',name)
    state=inspect(name)['State']
    if state['ExitCode'] != 0:
        raise RuntimeError('Container did not stop cleanly: '+str(state['ExitCode']))
    print('Docker UDP/TCP and SIGTERM smoke check passed')
finally:
    subprocess.run([sys.executable,'install.py','uninstall','--name',name],check=False)
