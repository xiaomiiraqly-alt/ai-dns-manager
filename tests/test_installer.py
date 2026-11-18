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

class ServiceAwareInstallerTests(unittest.TestCase):
    def test_manager_mode_uses_private_state_without_vpn_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'config').mkdir();(root/'config/manager.json').write_text('{}')
            calls=[]
            with patch.object(install,'ROOT',root),patch.object(install,'inspect',return_value=None),\
                 patch.object(install,'docker',side_effect=lambda *a,**k:calls.append(a)),\
                 patch.object(install.shutil,'which',return_value=None),\
                 patch.object(install.subprocess,'run',return_value=SimpleNamespace(returncode=0)),\
                 patch.object(install,'state_permissions_ready',side_effect=[False,True]):
                install.install('pilot',5353,None,service_aware=True)
            start=next(a for a in calls if a[:2]==('run','-d'))
            self.assertIn('ai_dns_manager.manager',start);self.assertIn('serve',start)
            self.assertIn('/state',start)
            self.assertIn('127.0.0.1:5353:5353/udp',start)
            self.assertTrue(any('CHOWN' in a for a in calls))
            self.assertFalse(any('--privileged' in a or 'amnezia-awg2' in a for a in calls))

    def test_existing_correct_state_skips_permission_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)/'service-state'
            with patch.object(install,'state_permissions_ready',return_value=True),\
                 patch.object(install,'docker') as docker:
                mount=install.prepare_state_directory(state,'image:test')
            self.assertIn(str(state),mount)
            docker.assert_not_called()
            self.assertTrue(state.is_dir())

    def test_existing_wrong_owner_uses_both_narrow_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)/'service-state'
            calls=[]
            with patch.object(install,'state_permissions_ready',side_effect=[False,True]),\
                 patch.object(install,'docker',side_effect=lambda *a,**k:calls.append(a)):
                install.prepare_state_directory(state,'image:test')
            self.assertEqual(len(calls),1)
            args=calls[0]
            self.assertIn('CHOWN',args)
            self.assertIn('FOWNER',args)
            self.assertIn('--network',args)
            self.assertIn('none',args)
            self.assertNotIn('--privileged',args)

    def test_permission_repair_must_actually_fix_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)/'service-state'
            with patch.object(install,'state_permissions_ready',return_value=False),\
                 patch.object(install,'docker') as docker:
                with self.assertRaisesRegex(RuntimeError,'Failed to prepare'):
                    install.prepare_state_directory(state,'image:test')
            docker.assert_called_once()

    def test_state_dir_symlink_is_refused_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)/'state'
            target=Path(tmp)/'elsewhere'
            target.mkdir()
            state.symlink_to(target, target_is_directory=True)
            with patch.object(install,'docker') as docker:
                with self.assertRaisesRegex(ValueError,'symlink'):
                    install.prepare_state_directory(state,'image:test')
            docker.assert_not_called()
