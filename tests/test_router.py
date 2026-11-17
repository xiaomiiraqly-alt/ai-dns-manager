import struct
import unittest
from ai_dns_manager.server import ProviderPool, match_domain, question_name, servfail

CONFIG = {"groups": {"default": ["1.1.1.1"], "ai": ["9.9.9.9", "8.8.8.8"]}, "default_group": "default", "rules": [{"domain": "example.com", "group": "ai"}]}

class RouterTests(unittest.TestCase):
    def test_suffix_boundary(self):
        self.assertTrue(match_domain("api.example.com", "example.com"))
        self.assertFalse(match_domain("fakeexample.com", "example.com"))
    def test_selection(self):
        p = ProviderPool(CONFIG)
        self.assertEqual(p.group_for("api.example.com"), "ai")
        self.assertEqual(p.group_for("example.org"), "default")
    def test_question(self):
        q = b"\x12\x34\x01\x00" + struct.pack("!HHHH", 1, 0, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01"
        self.assertEqual(question_name(q)[0], "example.com")
        self.assertEqual(servfail(q)[3] & 15, 2)
    def test_bad_config(self):
        with self.assertRaises(ValueError):
            ProviderPool({"groups": {"default": []}, "default_group": "default"})

if __name__ == "__main__":
    unittest.main()
