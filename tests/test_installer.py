"""Installer tests use a fake Docker state machine; do not touch real containers."""
import copy
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import install


class InstallerTests(unittest.TestCase):
    def test_unmanaged_container_refused(self):
        with patch.object(install,'inspect',return_value={'Config':{'Labels':{}}}):
            with self.assertRaises(ValueError):
                install.require_owned('existing-service')

    def test_backup_not_overwritten(self):
        with patch.object(install,'require_owned',return_value={'managed':True}),patch.object(install,'docker') as docker:
            with self.assertRaises(ValueError):
                install.install('ai-dns-manager',5353,None)
            docker.assert_not_called()

    def exercise(self, fail=False, old=False):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'config').mkdir();(root/'config/router.json').write_text('{}')
            info={'Config':{'Labels':{install.LABEL:'true'}}}
            states={'pilot':copy.deepcopy(info)} if old else {}
            calls=[]
            def fake(*args,**kw):
                calls.append(args)
                if args[0]=='stop' or args[0]=='start':
                    return ''
                if args[0]=='rename':
                    states[args[2]]=states.pop(args[1]);return ''
                if args[0]=='rm':
                    states.pop(args[-1],None);return ''
                if args[0]=='run' and '-d' in args:
                    name=args[args.index('--name')+1]
                    states[name]=copy.deepcopy(info)
                    if fail:
                        raise subprocess.CalledProcessError(1,['docker','run'])
                return ''
            with patch.object(install,'ROOT',root),patch.object(install,'inspect',side_effect=lambda name:states.get(name)),\
                 patch.object(install,'docker',side_effect=fake),patch.object(install.shutil,'which',return_value=None),\
                 patch.object(install.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
                if fail:
                    with self.assertRaises(subprocess.CalledProcessError):
                        install.install('pilot',5353,None)
                else:
                    install.install('pilot',5353,None)
            return states,calls

    def test_failed_update_restores_previous_container(self):
        states,calls=self.exercise(fail=True,old=True)
        self.assertIn('pilot',states)
        self.assertNotIn('pilot-rollback',states)
        self.assertIn(('start','pilot'),calls)

    def test_first_install_is_loopback_and_unprivileged(self):
        states,calls=self.exercise()
        start=next(args for args in calls if args[:2]==('run','-d'))
        self.assertIn('127.0.0.1:5353:5353/udp',start)
        self.assertIn('--read-only',start)
        self.assertNotIn('--privileged',start)
        self.assertNotIn('host',start)
        self.assertIn('pilot',states)
