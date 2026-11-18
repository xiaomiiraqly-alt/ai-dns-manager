"""Safety contract for isolated Karakeep split DNS; no real Docker commands."""
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import karakeep_split_dns as k


class DNSClientTests(unittest.TestCase):
    def test_preserves_original_nameservers_and_search_options(self):
        before='search karakeep_default\nnameserver 127.0.0.11\nnameserver 1.1.1.1\noptions ndots:0\n'
        self.assertEqual(k.nameservers(before),['127.0.0.11','1.1.1.1'])
        new=k.rewrite_resolv(before)
        self.assertIn('nameserver 127.0.0.53\n',new)
        self.assertIn('search karakeep_default',new)
        self.assertIn('options ndots:0',new)
        self.assertNotIn('nameserver 1.1.1.1',new)

    def test_no_original_resolver_must_fail(self):
        with self.assertRaises(ValueError):
            k.rewrite_resolv('options ndots:0\n')

    def test_required_service_never_falls_back_to_direct_dns(self):
        required={'id':'gemini-api','mode':'required',
                  'routes':['generativelanguage.googleapis.com']}
        pref={'id':'other','mode':'preferred','routes':['api.example.com']}
        c=k.config_for('10.8.1.1',['127.0.0.11','9.9.9.9'],[required,pref])
        self.assertEqual(len(c['groups']['mandatory']),1)
        self.assertEqual(c['groups']['mandatory'][0]['ip'],'10.8.1.1')
        self.assertEqual([x['ip'] for x in c['groups']['standard']],
                         ['127.0.0.11','9.9.9.9'])
        self.assertEqual([x['ip'] for x in c['groups']['preferred']],
                         ['10.8.1.1','127.0.0.11','9.9.9.9'])
        self.assertEqual([x['group'] for x in c['rules']],
                         ['mandatory','preferred'])
        self.assertEqual(c['allowed_clients'],['127.0.0.0/8'])

    def test_nonprivate_gateway_refused(self):
        with self.assertRaises(ValueError):
            k.config_for('8.8.8.8',['127.0.0.11'],[])

    def test_runtime_dns_files_are_only_expected_container_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            con=root/'containers'/'abc';con.mkdir(parents=True)
            p=con/'resolv.conf';p.write_text('nameserver 127.0.0.11\n')
            own={'State':{'Running':True,'Pid':os.getpid()},'Id':'abc',
                 'ResolvConfPath':str(p)}
            with patch.object(k,'docker_root',return_value=root),\
                 patch.object(k,'inspect',return_value=own):
                found=k.target_files('awg',('web','chrome'))
            self.assertEqual(len(found),1)
            self.assertEqual(len(found[p]['containers']),2)
            self.assertEqual(found[p]['before'],'nameserver 127.0.0.11\n')

    def test_refuse_containers_outside_awg_namespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'containers'/'abc'/'resolv.conf'
            p.parent.mkdir(parents=True);p.write_text('nameserver 1.1.1.1\n')
            awg={'State':{'Running':True,'Pid':os.getpid()}}
            web={'State':{'Running':True,'Pid':999999999},'Id':'abc',
                 'ResolvConfPath':str(p)}
            with patch.object(k,'inspect',side_effect=lambda n:awg if n=='awg' else web),\
                 patch.object(k,'docker_root',return_value=root):
                with self.assertRaises(OSError):
                    k.target_files('awg',('web',))

    def test_gateway_sidecar_has_no_public_port_or_vpn_mutation(self):
        commands=[]
        def run(*args,**kw):
            commands.append(args)
            return SimpleNamespace(returncode=0,stdout='container\n')
        with patch.object(k,'command',side_effect=run),\
             patch.object(k,'time') as t:
            t.sleep.return_value=None
            k.start_sidecar('image:test','karakeep-awg-client',Path('/tmp/mock.json'))
        launch=next(a for a in commands if a[:2]==('run','-d'))
        self.assertIn('container:karakeep-awg-client',launch)
        self.assertIn('127.0.0.53',launch)
        self.assertIn('NET_BIND_SERVICE',launch)
        self.assertNotIn('--publish',launch)
        self.assertNotIn('--privileged',launch)
        self.assertFalse(any(a[0] in ('restart','stop','kill','network','exec-host') for a in commands))

    def test_private_host_resolver_is_written_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'resolv.conf'
            p.write_text('nameserver 127.0.0.11\n')
            inode=p.stat().st_ino
            k.write_in_place(p,'nameserver 127.0.0.53\n')
            self.assertEqual(inode,p.stat().st_ino)
            self.assertEqual(p.read_text(),'nameserver 127.0.0.53\n')

    def test_apply_and_rollback_preserves_original_docker_resolver(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            path=root/'containers'/'web'/'resolv.conf'
            path.parent.mkdir(parents=True)
            original='search karakeep_default\nnameserver 127.0.0.11\noptions ndots:0\n'
            path.write_text(original)
            info={'State':{'Running':True},
                  'Config':{'Labels':{k.OWNER:'true'}}}
            found={path:{'containers':[{'name':'web','id':'web-id'}],'before':original}}
            owned_web={'Id':'web-id'}
            def insp(name):
                if name==k.SIDECAR:
                    return info
                return owned_web
            def run(*a,**kw):
                return SimpleNamespace(returncode=0,stdout='')
            with patch.object(k,'ROOT',root),patch.object(k,'STATE',root/'local'/'karakeep-split-dns'),\
                 patch.object(k,'inspect',side_effect=lambda n:None if n==k.SIDECAR else owned_web),\
                 patch.object(k,'target_files',return_value=found),\
                 patch.object(k,'command',side_effect=run),\
                 patch.object(k,'start_sidecar'),\
                 patch.object(k,'run_gateway_check'),\
                 patch.object(k,'run_local_check'):
                k.provision('10.8.1.1','awg',('web',))
            self.assertIn('127.0.0.53',path.read_text())
            with patch.object(k,'ROOT',root),patch.object(k,'STATE',root/'local'/'karakeep-split-dns'),\
                 patch.object(k,'inspect',side_effect=insp),\
                 patch.object(k,'command',side_effect=run):
                k.remove()
            self.assertEqual(path.read_text(),original)

    def test_failed_gateway_check_keeps_original_resolver(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            path=root/'containers'/'web'/'resolv.conf'
            path.parent.mkdir(parents=True)
            original='nameserver 127.0.0.11\n'
            path.write_text(original)
            found={path:{'containers':[{'name':'web','id':'id'}],'before':original}}
            info={'State':{'Running':True},
                  'Config':{'Labels':{k.OWNER:'true'}}}
            with patch.object(k,'ROOT',root),patch.object(k,'STATE',root/'local'/'karakeep-split-dns'),\
                 patch.object(k,'inspect',side_effect=lambda n:None if n==k.SIDECAR else info),\
                 patch.object(k,'target_files',return_value=found),\
                 patch.object(k,'command',return_value=SimpleNamespace(returncode=0,stdout='')),\
                 patch.object(k,'start_sidecar'),\
                 patch.object(k,'run_gateway_check',side_effect=ValueError('gateway unavailable')):
                with self.assertRaisesRegex(ValueError,'gateway unavailable'):
                    k.provision('10.8.1.1','awg',('web',))
            self.assertEqual(path.read_text(),original)
            self.assertFalse((root/'local'/'karakeep-split-dns'/'manifest.json').exists())


if __name__=='__main__':
    unittest.main()
