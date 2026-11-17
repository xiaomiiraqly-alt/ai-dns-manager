import json
import unittest
from unittest.mock import patch
from ai_dns_manager.doh import doh_query


class FakeResponse:
    status = 200
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, n):
        return json.dumps({"Status": 0, "Answer": [{"type": 1, "data": "203.0.113.7"}]}).encode()


class DoHTests(unittest.TestCase):
    @patch("urllib.request.urlopen", return_value=FakeResponse())
    def test_valid_json_response(self, mock_open):
        self.assertEqual(doh_query("example.com", "https://dns.example/dns-query", 2), ["203.0.113.7"])
        self.assertIn("name=example.com", mock_open.call_args.args[0].full_url)

    def test_reject_http(self):
        with self.assertRaises(ValueError):
            doh_query("example.com", "http://dns.example/dns-query", 2)

    def test_reject_credentials(self):
        with self.assertRaises(ValueError):
            doh_query("example.com", "https://user:pass@dns.example/dns-query", 2)


if __name__ == "__main__":
    unittest.main()
