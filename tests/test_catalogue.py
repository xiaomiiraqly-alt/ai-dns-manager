import json
from pathlib import Path
import tempfile
import unittest
from ai_dns_manager.catalogue import parse_feed,update_source,merge_catalogues,expand_providers,normalize_provider,endpoint_id


def source():return {'id':'test','format':'aidns-v1','urls':['https://raw.githubusercontent.com/a/b/main/providers.json'],'refresh_seconds':21600}
def raw(ip='1.1.1.1'):
    return json.dumps({'schemaVersion':1,'providers':[{'id':'test','name':'Example','ipv4':[ip],'hosts':['dns.example.com'],'doh':['https://dns.example.com/dns-query']}]}).encode()


class CatalogueTests(unittest.TestCase):
    def test_original_and_presets(self):
        parsed=parse_feed(Path('config/providers.seed.json').read_bytes(),'aidns-v1','bundled')
        self.assertGreaterEqual(len(parsed['providers']),15)
        p=parse_feed(b'x | Name | desc | 1.1.1.1, 9.9.9.9 | https://dns.example.com/dns-query','dnsswitch','test')
        self.assertEqual(p['providers'][0]['ipv4'],['1.1.1.1','9.9.9.9'])
    def test_private_and_bad_endpoints_removed(self):
        value=normalize_provider({'id':'safe','ipv4':['127.0.0.1','169.254.169.254','10.0.0.1','1.1.1.1'],'doh':['http://bad.test/query','https://x:y@bad.test/dns']},'test')
        self.assertEqual(value['ipv4'],['1.1.1.1']);self.assertEqual(value['doh'],[])
    def test_empty_bad_version_oversized_rejected(self):
        for value in [b'{}',b'{"schemaVersion":2,"providers":[]}',b'x'*1048577]:
            with self.assertRaises(ValueError):parse_feed(value,'aidns-v1','test')
    def test_valid_cache_reused_for_six_hours(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=update_source(source(),tmp,fetcher=lambda u:raw(),clock=lambda:100)
            def fail(u):raise AssertionError('Should use cache')
            b=update_source(source(),tmp,fetcher=fail,clock=lambda:200)
            self.assertEqual(a['origin'],'remote');self.assertEqual(b['origin'],'cache')
    def test_failed_download_keeps_last_good(self):
        with tempfile.TemporaryDirectory() as tmp:
            update_source(source(),tmp,fetcher=lambda u:raw(),clock=lambda:100)
            file=next(Path(tmp).iterdir());before=file.read_bytes()
            out=update_source(source(),tmp,force=True,fetcher=lambda u:b'{"broken":true}',clock=lambda:22000)
            self.assertEqual(out['origin'],'stale-cache');self.assertEqual(file.read_bytes(),before)
    def test_offline_no_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            def fail(u):raise AssertionError('Offline must not download')
            self.assertEqual(update_source(source(),tmp,offline=True,fetcher=fail)['origin'],'unavailable')
    def test_changed_source_identity_cannot_reuse_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            update_source(source(),tmp,fetcher=lambda u:raw())
            new=source();new['urls']=['https://raw.githubusercontent.com/other/b/main/providers.json']
            self.assertEqual(update_source(new,tmp,offline=True)['origin'],'unavailable')
    def test_duplicates_merged_with_provenance(self):
        a=normalize_provider({'id':'first','ipv4':['1.1.1.1']},'one')
        b=normalize_provider({'id':'second','ipv4':['1.1.1.1','9.9.9.9']},'two')
        out=merge_catalogues([a,b]);self.assertEqual(len(out),1)
        self.assertEqual(set(out[0]['sources']),{'one','two'})
    def test_discovery_rejects_private_address(self):
        p=normalize_provider({'id':'test','ipv4':['1.1.1.1'],'hosts':['dns.example.com'],'doh':['https://dns.example.com/dns-query']},'local')
        out=expand_providers([p],[],resolver=lambda host:['127.0.0.1'])
        self.assertTrue(all((c['upstream'].get('ip') or c['upstream'].get('bootstrap_ip'))=='1.1.1.1' for c in out))
    def test_retired_endpoint_removed(self):
        p=normalize_provider({'id':'test','ipv4':['1.1.1.1','9.9.9.9']},'local')
        self.assertEqual(merge_catalogues([p],retired={'1.1.1.1'})[0]['ipv4'],['9.9.9.9'])
    def test_endpoint_identity_does_not_depend_on_provider_name(self):
        self.assertEqual(endpoint_id({'name':'a','ip':'1.1.1.1'}),endpoint_id({'name':'b','ip':'1.1.1.1'}))

class CatalogueSafetyTests(unittest.TestCase):
    def test_reference_identity_cannot_be_spoofed(self):
        with self.assertRaises(ValueError):normalize_provider({'id':'reference','ipv4':['1.1.1.1']},'remote')
    def test_disallowed_source_url_rejected_before_socket(self):
        from ai_dns_manager.catalogue import download
        from unittest.mock import patch
        for url in ['http://raw.githubusercontent.com/a/b','https://evil.example/feed','https://127.0.0.1/feed','https://raw.githubusercontent.com/a/b?secret=x']:
            with patch('socket.getaddrinfo') as net,self.assertRaises(ValueError):
                download(url)
                net.assert_not_called()
