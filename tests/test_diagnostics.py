import unittest
from unittest.mock import patch
from ai_dns_manager.__main__ import dns_query, check_tls
from ai_dns_manager.gemini import classify


class DiagnosticsTests(unittest.TestCase):
    def test_invalid_dns_name(self):
        with self.assertRaises(ValueError):
            dns_query('a'*64 + '.example','127.0.0.1',.1)

    def test_tls_failure_is_reported(self):
        with patch('socket.create_connection',side_effect=TimeoutError('timed out')):
            result=check_tls('example.com','1.1.1.1',.1)
        self.assertFalse(result['ok'])
        self.assertEqual(result['error'],'TimeoutError')

    def test_private_probe_skipped(self):
        with patch('socket.create_connection') as mock:
            self.assertFalse(check_tls('example.com','127.0.0.1',1)['ok'])
            mock.assert_not_called()

    def test_gemini_array_region_error(self):
        data=[{'error':{'code':400,'message':'User location is not supported for the API use.','status':'FAILED_PRECONDITION'}}]
        self.assertEqual(classify(400,data),'REGION_BLOCKED')

    def test_quota_not_region(self):
        self.assertEqual(classify(429,{'error':{'message':'quota'}}),'QUOTA_OR_RATE_LIMIT')

    def test_auth_not_route_failure(self):
        self.assertEqual(classify(403,{'error':{'message':'API key invalid'}}),'AUTH_OR_PERMISSION')

    def test_empty_generation_not_success(self):
        self.assertEqual(classify(200,{'choices':[{'message':{'content':''}}]}),'EMPTY_GENERATION')

    def test_real_generation(self):
        self.assertEqual(classify(200,{'choices':[{'message':{'content':'OK'}}]}),'GENERATION_OK')
