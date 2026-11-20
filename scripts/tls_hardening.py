"""TLS Cryptographic Cipher Suite Auditor & Certificate Ingress Validator.

Enforces Forward Secrecy, modern TLS protocol versions (TLS 1.2+ / TLS 1.3),
HSTS headers, and audits X.509 PEM certificate chains for edge reverse proxies.
"""

from __future__ import annotations

import base64
import datetime
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class TlsSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class TlsAuditFinding:
    rule_id: str
    severity: TlsSeverity
    message: str
    recommendation: str


# Insecure legacy protocols
DEPRECATED_PROTOCOLS: Set[str] = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

# Banned weak ciphers (broken algorithms or vulnerable modes)
BANNED_CIPHER_SUBSTRINGS: Tuple[str, ...] = (
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "NULL",
    "EXPORT",
    "anon",
    "CBC",  # Vulnerable to padding oracle (Lucky13, POODLE)
)

# Mandatory modern authenticated ciphers (AEAD)
PREFERRED_AEAD_CIPHERS: Set[str] = {
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
}


@dataclass
class TlsAuditReport:
    is_compliant: bool
    findings: List[TlsAuditFinding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == TlsSeverity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == TlsSeverity.WARNING)


def audit_tls_configuration(
    protocols: List[str],
    ciphers: List[str],
    headers: Optional[Dict[str, str]] = None,
) -> TlsAuditReport:
    """Audit TLS protocols, cipher suites, and security headers against NSA/Mozilla modern guidelines."""
    findings: List[TlsAuditFinding] = []

    # 1. Protocol version checks
    for proto in protocols:
        norm_proto = proto.strip()
        if norm_proto in DEPRECATED_PROTOCOLS:
            findings.append(TlsAuditFinding(
                rule_id="TLS-PROTO-001",
                severity=TlsSeverity.CRITICAL,
                message=f"Deprecated and insecure protocol enabled: '{norm_proto}'",
                recommendation="Disable all SSL and TLS versions older than TLSv1.2; prefer TLSv1.3 exclusively.",
            ))

    has_modern = any("TLSv1.2" in p or "TLSv1.3" in p for p in protocols)
    if not has_modern:
        findings.append(TlsAuditFinding(
            rule_id="TLS-PROTO-002",
            severity=TlsSeverity.CRITICAL,
            message="No modern TLS protocol enabled (missing TLSv1.2 and TLSv1.3)",
            recommendation="Enable 'TLSv1.2 TLSv1.3' in ssl_protocols directive.",
        ))

    # 2. Cipher suite checks
    for cipher in ciphers:
        norm_c = cipher.strip()
        for banned in BANNED_CIPHER_SUBSTRINGS:
            if banned in norm_c:
                findings.append(TlsAuditFinding(
                    rule_id="TLS-CIPHER-001",
                    severity=TlsSeverity.CRITICAL,
                    message=f"Weak or broken cipher suite allowed: '{norm_c}' contains '{banned}'",
                    recommendation="Remove legacy ciphers and configure an explicit AEAD-only cipher suite list.",
                ))
                break

    # Check for Forward Secrecy (PFS)
    has_forward_secrecy = any("ECDHE" in c or "DHE" in c or "TLS_AES" in c or "CHACHA" in c for c in ciphers)
    if not has_forward_secrecy and ciphers:
        findings.append(TlsAuditFinding(
            rule_id="TLS-CIPHER-002",
            severity=TlsSeverity.CRITICAL,
            message="Cipher suites lack Perfect Forward Secrecy (missing ECDHE/DHE key exchange)",
            recommendation="Enforce ECDHE key exchanges to protect past sessions against private key compromise.",
        ))

    # 3. Security headers check (HSTS)
    if headers is not None:
        hsts = headers.get("Strict-Transport-Security") or headers.get("strict-transport-security")
        if not hsts:
            findings.append(TlsAuditFinding(
                rule_id="TLS-HSTS-001",
                severity=TlsSeverity.WARNING,
                message="Strict-Transport-Security (HSTS) header is missing",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
            ))
        else:
            if "max-age" not in hsts.lower():
                findings.append(TlsAuditFinding(
                    rule_id="TLS-HSTS-002",
                    severity=TlsSeverity.WARNING,
                    message="HSTS header is missing 'max-age' parameter",
                    recommendation="Specify 'max-age=31536000' (minimum 1 year) in HSTS header.",
                ))

    is_compliant = not any(f.severity == TlsSeverity.CRITICAL for f in findings)
    return TlsAuditReport(is_compliant=is_compliant, findings=findings)


def parse_and_validate_pem_certificate(pem_content: str) -> Dict[str, Any]:
    """Validate structure of a PEM encoded X.509 certificate and decode raw DER bytes."""
    if not pem_content or not isinstance(pem_content, str):
        raise ValueError("PEM content must be a non-empty string")

    cert_matches = re.findall(
        r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----",
        pem_content,
    )
    if not cert_matches:
        raise ValueError("No valid '-----BEGIN CERTIFICATE-----' block found in PEM input")

    certificates = []
    for idx, b64_block in enumerate(cert_matches):
        cleaned_b64 = re.sub(r"\s+", "", b64_block)
        try:
            der_bytes = base64.b64decode(cleaned_b64, validate=True)
        except Exception as exc:
            raise ValueError(f"Certificate {idx} has invalid base64 encoding: {exc}") from exc

        # DER sequence tag check (0x30)
        if len(der_bytes) < 32 or der_bytes[0] != 0x30:
            raise ValueError(f"Certificate {idx} is not a valid ASN.1 DER sequence")

        certificates.append({
            "index": idx,
            "byte_length": len(der_bytes),
            "is_der_sequence": True,
        })

    return {
        "certificate_count": len(certificates),
        "certificates": certificates,
    }
