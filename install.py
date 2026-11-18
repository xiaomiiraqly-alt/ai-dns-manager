#!/usr/bin/env python3
"""Install a loopback-only pilot. Never edits host DNS, firewall or VPN settings."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
LABEL = 'io.github.xiaomiiraqly-alt.ai-dns-manager'


def docker(*args, capture=False):
    result = subprocess.run(['docker', *args], cwd=ROOT, check=True,
                            text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout if capture else ''


def inspect(name):
    result = subprocess.run(['docker', 'container', 'inspect', name], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return json.loads(result.stdout)[0] if result.returncode == 0 else None


def require_owned(name):
    info = inspect(name)
    if info and (info['Config'].get('Labels') or {}).get(LABEL) != 'true':
        raise ValueError('Refusing to change unmanaged container: ' + name)
    return info


def rollback(name):
    backup = name + '-rollback'
    old, current = require_owned(backup), require_owned(name)
    if not old:
        raise ValueError('No rollback container exists')
    if current:
        docker('rm', '-f', name)
    docker('rename', backup, name)
    docker('start', name)
    print('Previous image and configuration snapshot restored; inspect health status.')


def state_permissions_ready(state):
    """A running service already owns its private writable state directory.

    Repeating chmod as root inside a CAP_CHOWN-only helper fails with EPERM
    once the directory belongs to UID 65534. Check before modifying it.
    """
    info = state.stat()
    return (info.st_uid == 65534 and info.st_gid == 65534
            and stat.S_IMODE(info.st_mode) == 0o700)


def prepare_state_directory(state, image):
    """Set ownership only when required; never follow a state-dir symlink."""
    if state.is_symlink():
        raise ValueError('Refusing a symlinked state directory')
    state.mkdir(mode=0o700, exist_ok=True)
    if not state.is_dir():
        raise ValueError('State directory must be a directory')
    mount = 'type=bind,source='+str(state)+',target=/state'
    if not state_permissions_ready(state):
        # This helper runs without network, with only the two capabilities
        # required to repair both root-owned and 65534-owned directories.
        # FOWNER is necessary for chmod of a directory already owned by
        # nobody; CHOWN is necessary for a first-time root-owned directory.
        docker('run','--rm','--network','none','--read-only','--user','0:0',
               '--cap-drop','ALL','--cap-add','CHOWN','--cap-add','FOWNER',
               '--security-opt','no-new-privileges','--mount',mount,
               '--entrypoint','python',image,'-c',
               "import os; os.chmod('/state',0o700); os.chown('/state',65534,65534)")
        if not state_permissions_ready(state):
            raise RuntimeError('Failed to prepare private state directory ownership/mode')
    return mount


def install(name, port, config, service_aware=False, secrets_file=None, archive_rollback=False):
    backup = name + '-rollback'
    old = require_owned(name)
    if require_owned(backup) and not archive_rollback:
        raise ValueError('A rollback snapshot already exists; use --archive-rollback to retain it safely')
    local = ROOT / 'local'
    local.mkdir(mode=0o700, exist_ok=True)
    if config is None:
        config = local / ('manager.json' if service_aware else 'router.json')
        if not config.exists():
            shutil.copyfile(ROOT / ('config/manager.json' if service_aware else 'config/router.json'), config)
    config = config.resolve(strict=True)
    secret_args=[]
    if service_aware and secrets_file is None:
        # Persistent root-owned credential provisioning is a one-time action.
        # Subsequent software updates automatically remount this same file.
        default_secret=Path('/etc/ai-dns-manager/gemini.env')
        if default_secret.is_file():
            secrets_file=default_secret
    if secrets_file is not None:
        secrets_file=Path(secrets_file).resolve(strict=True)
        if not service_aware or ROOT in secrets_file.parents or secrets_file.stat().st_mode & 0o077:
            raise ValueError('Service-aware secrets file must be outside the checkout, with permissions 600 or stricter')
        if secrets_file.stat().st_size>65536:
            raise ValueError('Secrets file is too large')
        from ai_dns_manager.manager import settings
        _,definitions=settings(config)
        allowed={v for service in definitions for key,v in service.get('auth',{}).items() if key in ('key_env','model_env')}
        if any(service['id']=='gemini-api' for service in definitions):
            allowed.update(('OPENAI_API_KEY','INFERENCE_TEXT_MODEL'))
        for line in secrets_file.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith('#'):continue
            key,separator,value=line.partition('=')
            if not separator or key not in allowed or '\0' in value:
                raise ValueError('Secrets file contains an unexpected variable; use SERVICE_API_KEY/SERVICE_MODEL names from the local service definitions')
        secret_args=['--env-file',str(secrets_file)]
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    instances = local / 'instances'
    instances.mkdir(mode=0o700, exist_ok=True)
    snapshot = instances / stamp
    snapshot.mkdir(mode=0o700)
    config_copy = snapshot / 'router.json'
    shutil.copyfile(config, config_copy)
    # Private host directory; mounted file must be readable by container UID 65534.
    config_copy.chmod(0o644)
    rev = 'local'
    if shutil.which('git'):
        result = subprocess.run(['git', 'rev-parse', '--short=12', 'HEAD'], cwd=ROOT,
                                text=True, capture_output=True)
        if result.returncode == 0:
            rev = result.stdout.strip()
    image = 'ai-dns-manager:' + rev
    mount = 'type=bind,source=' + str(config_copy) + ',target=/app/config/router.json,readonly'
    security = ['--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges']
    docker('build', '--build-arg', 'VCS_REF=' + rev, '-t', image, '.')
    module='ai_dns_manager.manager' if service_aware else 'ai_dns_manager.server'
    validate=['validate','--config','/app/config/router.json'] if service_aware else ['--check-config']
    docker('run', '--rm', '--network', 'none', *security, '--mount', mount,
           '--entrypoint', 'python', image, '-m', module, *validate)
    state_args=[]
    command=['--listen','0.0.0.0','--port','5353']
    if service_aware:
        state=local / 'service-state'
        state_mount=prepare_state_directory(state,image)
        state_args=['--mount',state_mount]
        command=['serve','--config','/app/config/router.json','--state-dir','/state',*command]
    moved, attempting_new = False, False
    try:
        if archive_rollback and require_owned(backup):
            archive=backup+'-'+stamp
            if require_owned(archive):
                raise ValueError('An archived snapshot already exists with this name')
            docker('rename', backup, archive)
            print('Preserved older rollback as:', archive)
        if old:
            docker('stop', name)
            docker('rename', name, backup)
            moved = True
        attempting_new = True
        docker('run', '-d', '--name', name, '--label', LABEL + '=true',
               '--restart', 'unless-stopped', '--network', 'bridge', *security,
               '--pids-limit', '128', '--memory', '192m',
               '--log-driver', 'json-file', '--log-opt', 'max-size=5m', '--log-opt', 'max-file=3',
               '--publish', f'127.0.0.1:{port}:5353/udp', '--publish', f'127.0.0.1:{port}:5353/tcp',
               '--mount', mount, *state_args, *secret_args, '--health-cmd', 'python -m ai_dns_manager.healthcheck',
               '--health-interval', '10s', '--health-timeout', '5s', '--health-retries', '3',
               '--health-start-period', '5s', '--entrypoint', 'python', image,
               '-m', module, *command)
        for _ in range(30):
            result = subprocess.run(['docker','exec',name,'python','-m','ai_dns_manager.healthcheck'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                print(f'Installed local DNS listener at 127.0.0.1:{port} UDP/TCP.')
                if service_aware:
                    print('AI route selection is ASYNCHRONOUS; readiness requires a valid active-plan.json.')
                    print('Check progress: docker exec '+name+' python -m ai_dns_manager.manager status --config /app/config/router.json --state-dir /state')
                    print('Scan progress: local/service-state/scan-progress.json')
                print('Host DNS, VPN clients, and firewall were NOT modified. AI API success is NOT implied.')
                return
            time.sleep(1)
        raise RuntimeError('Local listener healthcheck failed')
    except BaseException:
        try:
            if moved:
                if require_owned(name):
                    docker('rm', '-f', name)
                docker('rename', backup, name)
                docker('start', name)
            elif old:
                docker('start', name)
            elif attempting_new and require_owned(name):
                docker('rm', '-f', name)
        except Exception as error:
            print('Automatic rollback failed: ' + type(error).__name__, file=sys.stderr)
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', nargs='?', default='install', choices=['install','status','rollback','uninstall'])
    p.add_argument('--name', default='ai-dns-manager')
    p.add_argument('--port', type=int, default=5353)
    p.add_argument('--config', type=Path)
    p.add_argument('--service-aware', action='store_true', help='Run the service selector, auto-updates and monitor, still loopback-only')
    p.add_argument('--archive-rollback', action='store_true', help='Preserve an older rollback under a timestamped name before upgrading')
    p.add_argument('--secrets-file', type=Path, help='Optional local Docker env-file outside the repository; never uploaded')
    args = p.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', args.name) or not 1024 <= args.port <= 65535:
        p.error('Invalid container name or unprivileged port')
    if not shutil.which('docker'):
        p.error('Docker Engine is required; Compose is not needed')
    try:
        docker('info', capture=True)
        require_owned(args.name)
        require_owned(args.name + '-rollback')
        if args.action == 'install':
            install(args.name,args.port,args.config,args.service_aware,args.secrets_file,args.archive_rollback)
        elif args.action == 'rollback':
            rollback(args.name)
        elif args.action == 'status':
            info = inspect(args.name)
            print(json.dumps({'container':args.name,'state':info['State'] if info else 'absent'}, indent=2))
        else:
            for name in (args.name,args.name+'-rollback'):
                if require_owned(name):
                    docker('rm','-f',name)
            print('Managed containers removed; configs and images retained.')
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        p.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
