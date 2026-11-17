"""Encrypted DNS integration tests with a local temporary CA, never disabled TLS."""
import http.server
import shutil
import socketserver
import ssl
import subprocess
import tempfile
from pathlib import Path
import unittest
from ai_dns_manager import wire
from ai_dns_manager.transports import Upstream, exchange
from helpers import running, TCP, answer


class HTTPSHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        query=self.rfile.read(int(self.headers['Content-Length']))
        response=answer(query)
        self.send_response(self.server.code)
        self.send_header('Content-Type',self.server.mime)
        self.send_header('Content-Length',str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class EncryptedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('openssl'):
            raise unittest.SkipTest('openssl required for local TLS fixture')
        cls.tmp=tempfile.TemporaryDirectory()
        cert,key=Path(cls.tmp.name)/'cert.pem',Path(cls.tmp.name)/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),
            '-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cls.server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_context.load_cert_chain(str(cert),str(key))
        cls.client_context=ssl.create_default_context(cafile=str(cert))

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'tmp'):cls.tmp.cleanup()

    def test_dot_verified(self):
        server=socketserver.TCPServer(('127.0.0.1',0),TCP);server.calls=0
        server.socket=self.server_context.wrap_socket(server.socket,server_side=True)
        with running(server):
            up=Upstream.parse({'protocol':'dot','ip':'127.0.0.1','hostname':'localhost','port':server.server_address[1]})
            query=wire.make_query('example.com')
            self.assertEqual(wire.a_records(exchange(query,up,2,context=self.client_context)),['203.0.113.7'])

    def test_doh_verified_binary_message(self):
        server=http.server.HTTPServer(('127.0.0.1',0),HTTPSHandler)
        server.code,server.mime=200,'application/dns-message'
        server.socket=self.server_context.wrap_socket(server.socket,server_side=True)
        with running(server):
            up=Upstream.parse({'protocol':'doh','bootstrap_ip':'127.0.0.1',
                              'url':f'https://localhost:{server.server_address[1]}/dns-query'})
            query=wire.make_query('example.com')
            self.assertEqual(wire.a_records(exchange(query,up,2,context=self.client_context)),['203.0.113.7'])
            server.mime='text/html'
            with self.assertRaisesRegex(ValueError,'application/dns-message'):
                exchange(query,up,2,context=self.client_context)
            server.code=302
            with self.assertRaisesRegex(ValueError,'302'):
                exchange(query,up,2,context=self.client_context)

    def test_bad_hostname_rejected(self):
        server=socketserver.TCPServer(('127.0.0.1',0),TCP);server.calls=0
        server.socket=self.server_context.wrap_socket(server.socket,server_side=True)
        with running(server):
            up=Upstream.parse({'protocol':'dot','ip':'127.0.0.1','hostname':'wrong.invalid','port':server.server_address[1]})
            with self.assertRaises(ssl.SSLCertVerificationError):
                exchange(wire.make_query('example.com'),up,2,context=self.client_context)

    def test_reject_insecure_configuration(self):
        for url in ['http://localhost/dns-query','https://user:pass@localhost/dns-query','https://localhost/dns-query#x']:
            with self.subTest(url=url),self.assertRaises(ValueError):
                Upstream.parse({'protocol':'doh','ip':'127.0.0.1','url':url})

    def test_bootstrap_required(self):
        with self.assertRaises(ValueError):
            Upstream.parse({'protocol':'doh','url':'https://resolver.example/dns-query'})
