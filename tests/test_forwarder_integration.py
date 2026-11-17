"""Real loopback UDP/TCP, including truncated-UDP fallback; no Internet."""
import socket
import socketserver
import struct
import unittest
from ai_dns_manager import wire
from ai_dns_manager.server import ProviderPool, ThreadedUDP, ThreadedTCP, UDPHandler, TCPHandler, HEALTH_NAME, process
from ai_dns_manager.transports import Upstream, exchange
from helpers import running, UDP, TCP, answer


class IntegrationTests(unittest.TestCase):
    def test_udp_and_tcp_listeners(self):
        upstream=socketserver.UDPServer(('127.0.0.1',0),UDP)
        upstream.calls, upstream.truncated = 0, False
        with running(upstream):
            tcp_up=socketserver.TCPServer(upstream.server_address,TCP)
            tcp_up.calls=0
            with running(tcp_up):
                cfg={'groups':{'default':[{'ip':'127.0.0.1','port':upstream.server_address[1]}]},
                     'default_group':'default','health_interval_seconds':0}
                pool=ProviderPool(cfg)
                udp=ThreadedUDP(('127.0.0.1',0),UDPHandler)
                udp.pool=pool
                with running(udp):
                    tcp=ThreadedTCP(udp.server_address,TCPHandler)
                    tcp.pool=pool
                    with running(tcp):
                        local=Upstream.parse({'ip':'127.0.0.1','port':udp.server_address[1]})
                        query=wire.make_query('example.com')
                        for mode in (False,True):
                            self.assertEqual(wire.a_records(exchange(query,local,2,tcp=mode)),['203.0.113.7'])
                        for mode in (False,True):
                            health=wire.make_query(HEALTH_NAME)
                            self.assertEqual(wire.validate_response(health,exchange(health,local,2,tcp=mode)),0)
                        self.assertEqual(upstream.calls,1)
                        self.assertEqual(tcp_up.calls,1)

    def test_udp_truncation_retries_tcp(self):
        udp=socketserver.UDPServer(('127.0.0.1',0),UDP)
        udp.calls, udp.truncated=0,True
        with running(udp):
            tcp=socketserver.TCPServer(udp.server_address,TCP);tcp.calls=0
            with running(tcp):
                query=wire.make_query('example.com')
                up=Upstream.parse({'ip':'127.0.0.1','port':udp.server_address[1]})
                self.assertEqual(wire.a_records(exchange(query,up,2)),['203.0.113.7'])
                self.assertEqual(tcp.calls,1)

    def test_large_udp_result_sets_tc(self):
        def big(q,u,t,**kw):
            result=bytearray(answer(q))
            # Many valid A RRs, exceeding a classic UDP client's 512-byte limit.
            one=bytes(result[-16:])
            result[6:8]=struct.pack('!H',60)
            result.extend(one*59)
            return bytes(result)
        pool=ProviderPool({'groups':{'d':['1.1.1.1']},'default_group':'d'},exchanger=big)
        q=wire.make_query('example.com')
        out=process(pool,q)
        self.assertTrue(wire.header(out)[1] & 0x0200)
        self.assertLess(len(out),512)
        self.assertGreater(len(process(pool,q,tcp=True)),512)
