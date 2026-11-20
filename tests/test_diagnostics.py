"""Tests for RouteKernel static diagnostic analyzer."""
import pathlib
import unittest

from scripts.diagnostics import (
    run_diagnostics,
    ModernTlsRule,
    SecurityHeadersRule,
    ProxyBufferGeometryRule,
    Rfc7807ErrorPagesRule,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]


class DiagnosticsTests(unittest.TestCase):
    def test_run_diagnostics_on_repo(self):
        report = run_diagnostics(ROOT)
        self.assertEqual(report["totalRules"], 4)
        self.assertEqual(report["failed"], 0)
        self.assertTrue(report["healthy"])
        for res in report["results"]:
            self.assertEqual(res["status"], "PASS")

    def test_modern_tls_rule_catches_legacy_tls(self):
        rule = ModernTlsRule()
        content = {"nginx/nginx.conf": "ssl_protocols TLSv1.0 TLSv1.2 TLSv1.3;"}
        res = rule.evaluate(content)
        self.assertEqual(res["status"], "FAIL")

    def test_security_headers_rule_catches_missing_csp(self):
        rule = SecurityHeadersRule()
        content = {"nginx/conf.d/edge.conf": "add_header X-Frame-Options DENY always;"}
        res = rule.evaluate(content)
        self.assertEqual(res["status"], "FAIL")
        self.assertIn("Content-Security-Policy", res["missingHeaders"])

    def test_rfc7807_error_pages_detected(self):
        rule = Rfc7807ErrorPagesRule()
        res = rule.evaluate({
            "nginx/conf.d/edge.conf": (ROOT / "nginx/conf.d/edge.conf").read_text(encoding="utf-8")
        })
        self.assertEqual(res["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
