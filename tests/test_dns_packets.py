import struct
import unittest
from ai_dns_manager import wire
from helpers import answer


class WireTests(unittest.TestCase):
    def test_a_record_response(self):
        query = wire.make_query('example.com')
        response = answer(query)
        self.assertEqual(wire.validate_response(query, response), 0)
        self.assertEqual(wire.a_records(response), ['203.0.113.7'])

    def test_invalid_label(self):
        with self.assertRaises(ValueError):
            wire.make_query('x'*64 + '.com')

    def test_total_name_length(self):
        with self.assertRaises(ValueError):
            wire.make_query('.'.join(['x'*63]*4))

    def test_compression_loop(self):
        query = wire.make_query('example.com')
        with self.assertRaises(ValueError):
            wire.question(query[:12] + b'\xc0\x0c' + query[-4:])

    def test_out_of_bounds_pointer(self):
        with self.assertRaises(ValueError):
            wire.read_name(b'\0'*12 + b'\xff\xff', 12)

    def test_wrong_id(self):
        query = wire.make_query('example.com')
        with self.assertRaises(ValueError):
            wire.validate_response(query, b'\xff\xff' + answer(query)[2:] if query[:2] != b'\xff\xff' else b'\0\0' + answer(query)[2:])

    def test_wrong_question(self):
        query = wire.make_query('example.com')
        other = query[:2] + wire.make_query('example.net')[2:]
        with self.assertRaises(ValueError):
            wire.validate_response(query, answer(other))

    def test_malformed_rr(self):
        query = wire.make_query('example.com')
        with self.assertRaises(ValueError):
            wire.validate_response(query, answer(query)[:-1])

    def test_extra_bytes(self):
        query = wire.make_query('example.com')
        with self.assertRaises(ValueError):
            wire.validate_response(query, answer(query) + b'trailing')

    def test_response_is_not_query(self):
        with self.assertRaises(ValueError):
            wire.validate_query(answer(wire.make_query('example.com')))

    def test_zone_transfer_rejected(self):
        with self.assertRaises(ValueError):
            wire.validate_query(wire.make_query('example.com', 252))

    def test_servfail_preserves_question_and_id(self):
        query = wire.make_query('example.com')
        result = wire.reply(query)
        self.assertEqual(wire.validate_response(query, result), 2)

    def test_nxdomain_is_distinct(self):
        query = wire.make_query('example.com')
        self.assertEqual(wire.validate_response(query, answer(query, rcode=3)), 3)

    def test_udp_edns_cap(self):
        query = bytearray(wire.make_query('example.com'))
        query[10:12] = struct.pack('!H', 1)
        query += b'\0' + struct.pack('!HHIH', 41, 4096, 0, 0)
        self.assertEqual(wire.udp_limit(bytes(query)), 1232)
        self.assertEqual(wire.udp_limit(wire.make_query('example.com')), 512)
