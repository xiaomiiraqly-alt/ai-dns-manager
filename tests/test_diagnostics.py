import unittest
from unittest.mock import patch
from ai_dns_manager.__main__ import dns_query, check_tls


class DiagnosticsTests(unittest.TestCase):
    def test_invalid_dns_name(self):
        with self.assertRaises(ValueError):
            dns_query("a"*64 + ".example", "127.0.0.1", 0.1)

    def test_tls_failure_is_reported(self):
        with patch("socket.create_connection", side_effect=TimeoutError("timed out")):
            result = check_tls("example.com", "192.0.2.1", 0.1)
        self.assertFalse(result["ok"])
        self.assertIn("timed out", result["error"])


if __name__ == "__main__":
    unittest.main()
