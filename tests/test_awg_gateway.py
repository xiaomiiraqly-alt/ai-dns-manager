"""Offline integration contract for private WireGuard DNS gateway.

Mocks Docker; does not touch the host's real networking.
"""
import ipaddress
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import awg_dns_gateway as gateway


def owned(name, label):
    return {'Name':'/'+name, 'Config':{'Labels':{label:'true'},'Image':'ai-dns-manager:test'},
            'State':{'Running':True},
            'NetworkSettings':{'Networks':{}}}


class GatewayTests(unittest.TestCase):
    def test_reject_unverified_mandatory_plan(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'active-plan.json'
            def write(status, evidence=4):
                p.write_text(json.dumps({'applicable':True,
                    'checked_at':__import__('time').time(),
                    'routes':[{'service':'gemini-api','provider_id':'comss',
                               'status':status,'evidence':evidence}]}))
            for status, evidence in [('AUTH_GATE',1),('REGION_BLOCKED',0),
                                     ('GENERATION_OK',1)]:
                write(status, evidence)
                with self.subTest(status=status),self.assertRaises(ValueError):
                    gateway.active_generation(Path(folder))
            write('GENERATION_OK',4)
            self.assertEqual(gateway.active_generation(Path(folder)),'comss')

    def test_gateway_upstream_and_acl_are_private(self):
        ip=ipaddress.IPv4Interface('10.8.1.1/24')
        cfg=gateway.config_for('172.29.172.22',ip)
        self.assertEqual(cfg['allowed_clients'],['10.8.1.0/24','127.0.0.0/8'])
        self.assertEqual(cfg['groups']['manager'][0]['ip'],'172.29.172.22')
        self.assertEqual(cfg['groups']['manager'][0]['port'],5353)
        self.assertEqual(cfg['health_interval_seconds'],0)

    def test_public_wireguard_interface_refused(self):
        fake=SimpleNamespace(stdout='7: awg0 inet 8.8.8.8/24 scope global awg0')
        with patch.object(gateway,'command',return_value=fake):
            with self.assertRaises(ValueError):
                gateway.awg_address('amnezia-awg2','awg0')

    def test_unmanaged_container_refused(self):
        with self.assertRaises(ValueError):
            gateway.require_label({'Config':{'Labels':{}}},gateway.OWNER_LABEL,'other')

    def test_connecting_manager_preserves_default_gateway(self):
        old=owned('ai-dns-manager',gateway.MANAGER_LABEL)
        old['NetworkSettings']['Networks']={'bridge':{'IPAddress':'172.17.0.3'}}
        new=owned('ai-dns-manager',gateway.MANAGER_LABEL)
        new['NetworkSettings']['Networks']={'bridge':{'IPAddress':'172.17.0.3'},
                                          'amnezia-dns-net':{'IPAddress':'172.29.172.3'}}
        seen=[]
        with patch.object(gateway,'inspect',side_effect=[old,new]),\
             patch.object(gateway,'command',side_effect=lambda *x:seen.append(x)):
            self.assertEqual(gateway.ensure_manager_network('ai-dns-manager','amnezia-dns-net'),
                             '172.29.172.3')
        self.assertEqual(seen,[('network','connect','--gw-priority','-1',
                                'amnezia-dns-net','ai-dns-manager')])

    def test_private_gateway_started_without_public_port_or_vpn_mutation(self):
        awg=owned('amnezia-awg2','unused')
        awg['NetworkSettings']['Networks']={'amnezia-dns-net':{'IPAddress':'172.29.172.2'}}
        ai=owned('ai-dns-manager',gateway.MANAGER_LABEL)
        commands=[]
        def fake(*args,**kwargs):
            commands.append(args)
            return SimpleNamespace(stdout='1234567890abcdef\n',returncode=0)
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(gateway,'ROOT',Path(temp)),\
                 patch.object(gateway,'inspect',side_effect=lambda name:awg if name=='amnezia-awg2' else ai if name=='ai-dns-manager' else None),\
                 patch.object(gateway,'awg_address',return_value=ipaddress.IPv4Interface('10.8.1.1/24')),\
                 patch.object(gateway,'active_generation',return_value='dns-ai'),\
                 patch.object(gateway,'ensure_manager_network',return_value='172.29.172.22'),\
                 patch.object(gateway,'command',side_effect=fake):
                gateway.provision('ai-dns-manager','amnezia-awg2','amnezia-dns-net','awg0')
            launch=next(cmd for cmd in commands if cmd[:2]==('run','-d'))
            self.assertIn('container:amnezia-awg2',launch)
            self.assertIn('10.8.1.1',launch)
            self.assertIn('53',launch)
            self.assertIn('--read-only',launch)
            self.assertIn('NET_BIND_SERVICE',launch)
            self.assertNotIn('--privileged',launch)
            self.assertNotIn('--publish',launch)
            self.assertNotIn('-p',launch)
            self.assertFalse(any(cmd[0] in ('restart','stop','kill') for cmd in commands))

    def test_reject_private_vpn_gateway_without_verified_model_first(self):
        awg=owned('amnezia-awg2','unused')
        awg['NetworkSettings']['Networks']={'amnezia-dns-net':{'IPAddress':'172.29.172.2'}}
        calls=[]
        with patch.object(gateway,'inspect',side_effect=lambda name:awg if name=='amnezia-awg2' else None),\
             patch.object(gateway,'awg_address',return_value=ipaddress.IPv4Interface('10.8.1.1/24')),\
             patch.object(gateway,'active_generation',side_effect=ValueError('No generation')) as proof,\
             patch.object(gateway,'command',side_effect=lambda *x:calls.append(x)):
            with self.assertRaises(ValueError):
                gateway.provision('ai-dns-manager','amnezia-awg2','amnezia-dns-net','awg0')
        proof.assert_called_once()
        self.assertEqual(calls,[])


if __name__=='__main__':
    unittest.main()
