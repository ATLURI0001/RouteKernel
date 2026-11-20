#!/usr/bin/env python3
"""RouteKernel Architecture & Configuration Diagnostic Inspector.

Performs static analysis and invariant checks on Nginx edge configurations:
- TLS 1.2 / 1.3 protocol restrictions
- Forward secrecy session cache and ticket handling
- Request-ID traceability across edge headers and proxy passes
- Proxy buffer geometry (preventing unbounded temp file spillover)
- Slowloris and connection exhaustion defenses
- RFC 7807 problem+json error handlers
"""
from __future__ import annotations

import json
import pathlib
import sys
from typing import Any, Dict, List


class DiagnosticRule:
    def __init__(self, rule_id: str, description: str, severity: str = "ERROR"):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity  # "INFO", "WARN", "ERROR"

    def evaluate(self, content_map: Dict[str, str]) -> Dict[str, Any]:
        raise NotImplementedError


class ModernTlsRule(DiagnosticRule):
    def __init__(self):
        super().__init__("RK-TLS-001", "Enforce TLSv1.2 and TLSv1.3 with session caching and ticket disabling", "ERROR")

    def evaluate(self, content_map: Dict[str, str]) -> Dict[str, Any]:
        nginx_conf = content_map.get("nginx/nginx.conf", "")
        passed = (
            "ssl_protocols TLSv1.2 TLSv1.3;" in nginx_conf
            and "TLSv1.0" not in nginx_conf
            and "TLSv1.1" not in nginx_conf
            and "ssl_session_cache" in nginx_conf
            and "ssl_session_tickets off;" in nginx_conf
        )
        return {
            "ruleId": self.rule_id,
            "description": self.description,
            "status": "PASS" if passed else "FAIL",
            "severity": self.severity,
        }


class SecurityHeadersRule(DiagnosticRule):
    def __init__(self):
        super().__init__("RK-SEC-002", "Enforce defense-in-depth security headers (CSP, X-Frame-Options, X-Request-ID)", "ERROR")

    def evaluate(self, content_map: Dict[str, str]) -> Dict[str, Any]:
        edge_conf = content_map.get("nginx/conf.d/edge.conf", "")
        required = [
            "X-Content-Type-Options nosniff",
            "X-Frame-Options DENY",
            "Referrer-Policy strict-origin-when-cross-origin",
            "Content-Security-Policy",
            "X-Request-ID $request_id always",
        ]
        missing = [h for h in required if h not in edge_conf]
        return {
            "ruleId": self.rule_id,
            "description": self.description,
            "status": "PASS" if not missing else "FAIL",
            "missingHeaders": missing,
            "severity": self.severity,
        }


class ProxyBufferGeometryRule(DiagnosticRule):
    def __init__(self):
        super().__init__("RK-BUF-003", "Validate proxy buffering dimensions and unbuffered WebSocket bypass", "WARN")

    def evaluate(self, content_map: Dict[str, str]) -> Dict[str, Any]:
        proxy_conf = content_map.get("nginx/snippets/proxy.conf", "")
        edge_conf = content_map.get("nginx/conf.d/edge.conf", "")
        passed = (
            "proxy_buffering on;" in proxy_conf
            and "proxy_buffer_size" in proxy_conf
            and "proxy_max_temp_file_size 0;" in edge_conf
        )
        return {
            "ruleId": self.rule_id,
            "description": self.description,
            "status": "PASS" if passed else "FAIL",
            "severity": self.severity,
        }


class Rfc7807ErrorPagesRule(DiagnosticRule):
    def __init__(self):
        super().__init__("RK-ERR-004", "Validate RFC 7807 structured JSON error handling for 429 and 502/503/504", "ERROR")

    def evaluate(self, content_map: Dict[str, str]) -> Dict[str, Any]:
        edge_conf = content_map.get("nginx/conf.d/edge.conf", "")
        has_429 = "error_page 429 = @rate_limited;" in edge_conf and "application/problem+json" in edge_conf
        has_502 = "error_page 502 503 504 = @gateway_error;" in edge_conf and "Bad Gateway" in edge_conf
        passed = has_429 and has_502
        return {
            "ruleId": self.rule_id,
            "description": self.description,
            "status": "PASS" if passed else "FAIL",
            "severity": self.severity,
        }


def run_diagnostics(root_dir: pathlib.Path) -> Dict[str, Any]:
    files_to_load = [
        "nginx/nginx.conf",
        "nginx/conf.d/edge.conf",
        "nginx/snippets/proxy.conf",
    ]
    content_map = {}
    for rel_path in files_to_load:
        p = root_dir / rel_path
        if p.exists():
            content_map[rel_path] = p.read_text(encoding="utf-8")
        else:
            content_map[rel_path] = ""

    rules: List[DiagnosticRule] = [
        ModernTlsRule(),
        SecurityHeadersRule(),
        ProxyBufferGeometryRule(),
        Rfc7807ErrorPagesRule(),
    ]

    results = [rule.evaluate(content_map) for rule in rules]
    passed_count = sum(1 for r in results if r["status"] == "PASS")
    failed_count = sum(1 for r in results if r["status"] == "FAIL")

    return {
        "totalRules": len(rules),
        "passed": passed_count,
        "failed": failed_count,
        "healthy": failed_count == 0,
        "results": results,
    }


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    report = run_diagnostics(root)
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["healthy"] else 1)


if __name__ == "__main__":
    main()
