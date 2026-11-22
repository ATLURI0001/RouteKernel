import unittest
from scripts.rpki_validator import (
    RPKIStatus,
    ROARecord,
    RPKIRouteValidator,
)


class TestRPKIRouteValidator(unittest.TestCase):

    def setUp(self):
        self.validator = RPKIRouteValidator()

    def test_roa_record_validation(self):
        # Valid IPv4 and IPv6 ROAs
        r1 = ROARecord("192.0.2.0/24", 24, 64496)
        self.assertEqual(r1.prefix, "192.0.2.0/24")

        r2 = ROARecord("2001:db8::/32", 48, 64497)
        self.assertEqual(r2.max_length, 48)

        # max_length < prefixlen should raise
        with self.assertRaises(ValueError):
            ROARecord("198.51.100.0/24", 22, 64498)

        # Invalid ASN <= 0
        with self.assertRaises(ValueError):
            ROARecord("198.51.100.0/24", 24, 0)

    def test_validate_exact_valid_announcement(self):
        self.validator.add_roa("192.0.2.0/24", 24, 13335)
        res = self.validator.validate_announcement("192.0.2.0/24", 13335)

        self.assertEqual(res.status, RPKIStatus.VALID)
        self.assertFalse(res.is_hijack_risk)
        self.assertEqual(len(res.matched_roas), 1)

    def test_validate_subprefix_within_max_length(self):
        # Covered /16 authorized up to /24
        self.validator.add_roa("198.51.0.0/16", 24, 15169)
        res = self.validator.validate_announcement("198.51.10.0/24", 15169)

        self.assertEqual(res.status, RPKIStatus.VALID)
        self.assertFalse(res.is_hijack_risk)

    def test_validate_invalid_length_breach(self):
        # Covered /16 authorized only up to /20
        self.validator.add_roa("198.51.0.0/16", 20, 15169)
        # Announcement is /24 (> 20)
        res = self.validator.validate_announcement("198.51.10.0/24", 15169)

        self.assertEqual(res.status, RPKIStatus.INVALID_LENGTH)
        self.assertTrue(res.is_hijack_risk)
        self.assertIn("exceeds ROA max_length constraint", res.reason)

    def test_validate_invalid_asn_hijack_attempt(self):
        # ROA belongs to Cloudflare (13335)
        self.validator.add_roa("1.1.1.0/24", 24, 13335)
        # Rogue entity (99999) announces Cloudflare's prefix
        res = self.validator.validate_announcement("1.1.1.0/24", 99999)

        self.assertEqual(res.status, RPKIStatus.INVALID_ASN)
        self.assertTrue(res.is_hijack_risk)
        self.assertIn("does not match any covering ROA authorized ASN", res.reason)

    def test_validate_not_found_uncovered_prefix(self):
        res = self.validator.validate_announcement("203.0.113.0/24", 64500)
        self.assertEqual(res.status, RPKIStatus.NOT_FOUND)
        self.assertFalse(res.is_hijack_risk)

    def test_bulk_load_roas(self):
        roas = [
            {"prefix": "10.0.0.0/8", "max_length": 16, "asn": 100},
            {"prefix": "172.16.0.0/12", "max_length": 24, "asn": 200},
        ]
        count = self.validator.bulk_load_roas(roas)
        self.assertEqual(count, 2)

    def test_analyze_as_path(self):
        # Valid path
        valid_path = [174, 3356, 15169]
        res = self.validator.analyze_as_path(valid_path)
        self.assertTrue(res["valid"])
        self.assertEqual(res["origin_asn"], 15169)
        self.assertEqual(res["hop_count"], 3)

        # Loop detection
        loop_path = [174, 3356, 174, 15169]
        res_loop = self.validator.analyze_as_path(loop_path)
        self.assertFalse(res_loop["valid"])
        self.assertIn("Routing loop detected", res_loop["reason"])
        self.assertEqual(res_loop["loop_asn"], 174)

        # Private ASN leak
        private_path = [174, 64512, 15169]
        res_priv = self.validator.analyze_as_path(private_path)
        self.assertFalse(res_priv["valid"])
        self.assertIn("Private ASN leak detected", res_priv["reason"])

        # Empty path
        self.assertFalse(self.validator.analyze_as_path([])["valid"])

    def test_telemetry_and_clear(self):
        self.validator.add_roa("8.8.8.0/24", 24, 15169)
        self.validator.validate_announcement("8.8.8.0/24", 15169)
        self.validator.validate_announcement("8.8.8.0/24", 99999)

        telemetry = self.validator.get_telemetry()
        self.assertEqual(telemetry["total_validated"], 2)
        self.assertEqual(telemetry["valid_count"], 1)
        self.assertEqual(telemetry["invalid_asn_count"], 1)
        self.assertEqual(telemetry["hijacks_flagged"], 1)

        self.validator.clear()
        cleared = self.validator.get_telemetry()
        self.assertEqual(cleared["total_validated"], 0)


if __name__ == "__main__":
    unittest.main()
