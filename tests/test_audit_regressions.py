"""Audit regressions: incomplete address sampling and oscillating failover targets."""
import unittest
from ai_dns_manager.selection import Stability
from ai_dns_manager.service_scan import scan
from ai_dns_manager import wire
from helpers import answer


class AuditRegressions(unittest.TestCase):
    def test_partial_address_sampling_cannot_qualify_required_service(self):
        service = {
            'id': 'required-api', 'domain': 'api.example.com', 'kind': 'api',
            'mode': 'required', 'minimum_evidence': 'endpoint',
        }
        candidate = {
            'id': 'dns-a', 'provider_id': 'dns-a',
            'upstream': {'name': 'dns-a', 'ip': '1.1.1.1'},
        }
        # A DNS answer containing seventeen A records must not be marked eligible
        # when the scanner checked only the first sixteen.
        def dns(query, upstream, *args):
            result = bytearray(answer(query, ip='8.8.8.8'))
            result[6:8] = (17).to_bytes(2, 'big')
            one = bytes(result[-16:])
            for octet in range(9, 25):
                result.extend(one[:-1] + bytes([octet]))
            return bytes(result)
        def http(service, ip, **kwargs):
            return {'status': 'PUBLIC_API_OK', 'evidence': 2,
                    'latency_ms': 1, 'remote_ip': ip, 'tls_valid': True}
        report = scan([candidate], [service], dns_exchange=dns, http_probe=http)
        row = report['results'][0]
        self.assertTrue(row['partial_address_coverage'])
        self.assertFalse(row['eligible'])
        self.assertEqual(row['status'], 'PARTIAL_ADDRESS_COVERAGE')

    def test_alternating_targets_do_not_accumulate_switch_confirmation(self):
        stable = Stability(failures=2, hold_seconds=0)
        current = {'applicable': True, 'routes': [{'service': 'gemini-api', 'candidate': 'primary'}]}
        def plan(target):
            return {'applicable': True, 'routes': [{'service': 'gemini-api', 'candidate': target}]}
        self.assertFalse(stable.approve(plan('backup-a'), current, 0)[0])
        self.assertFalse(stable.approve(plan('backup-b'), current, 1)[0])
        self.assertFalse(stable.approve(plan('backup-a'), current, 2)[0])
        self.assertTrue(stable.approve(plan('backup-a'), current, 3)[0])

    def test_unavailable_required_resets_switch_confirmation(self):
        stable = Stability(failures=2, hold_seconds=0)
        current = {'applicable': True, 'routes': [{'service': 'gemini-api', 'candidate': 'primary'}]}
        proposed = {'applicable': True, 'routes': [{'service': 'gemini-api', 'candidate': 'backup'}]}
        self.assertFalse(stable.approve(proposed, current, 0)[0])
        self.assertFalse(stable.approve({'applicable': False, 'routes': []}, current, 1)[0])
        self.assertFalse(stable.approve(proposed, current, 2)[0])
        self.assertTrue(stable.approve(proposed, current, 3)[0])


if __name__ == '__main__':
    unittest.main()
