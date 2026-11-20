import base64
import sys
from pathlib import Path
import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from tls_hardening import (
    TlsSeverity,
    audit_tls_configuration,
    parse_and_validate_pem_certificate,
)


def test_audit_tls_configuration_compliant():
    protocols = ["TLSv1.2", "TLSv1.3"]
    ciphers = [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "TLS_AES_256_GCM_SHA384",
    ]
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    }
    report = audit_tls_configuration(protocols, ciphers, headers)
    assert report.is_compliant is True
    assert report.critical_count == 0
    assert report.warning_count == 0


def test_audit_tls_configuration_deprecated_protocols():
    protocols = ["TLSv1.0", "TLSv1.1"]
    ciphers = ["ECDHE-RSA-AES128-GCM-SHA256"]
    report = audit_tls_configuration(protocols, ciphers)
    assert report.is_compliant is False
    assert any(f.rule_id == "TLS-PROTO-001" for f in report.findings)
    assert any(f.rule_id == "TLS-PROTO-002" for f in report.findings)


def test_audit_tls_configuration_weak_ciphers():
    protocols = ["TLSv1.3"]
    ciphers = ["RC4-SHA", "DES-CBC3-SHA", "AES256-SHA"]
    report = audit_tls_configuration(protocols, ciphers)
    assert report.is_compliant is False
    assert any(f.rule_id == "TLS-CIPHER-001" for f in report.findings)
    assert any("RC4" in f.message for f in report.findings)


def test_audit_tls_configuration_missing_hsts():
    protocols = ["TLSv1.3"]
    ciphers = ["TLS_AES_256_GCM_SHA384"]
    report = audit_tls_configuration(protocols, ciphers, headers={})
    assert any(f.rule_id == "TLS-HSTS-001" and f.severity == TlsSeverity.WARNING for f in report.findings)


def test_parse_and_validate_pem_certificate():
    # Construct a valid synthetic DER sequence (starts with 0x30, length, then dummy bytes)
    dummy_der = bytes([0x30, 0x22]) + b"\x02\x01\x00" + b"\x00" * 31
    dummy_b64 = base64.b64encode(dummy_der).decode("ascii")
    pem_text = f"-----BEGIN CERTIFICATE-----\n{dummy_b64}\n-----END CERTIFICATE-----\n"

    res = parse_and_validate_pem_certificate(pem_text)
    assert res["certificate_count"] == 1
    assert res["certificates"][0]["byte_length"] == len(dummy_der)
    assert res["certificates"][0]["is_der_sequence"] is True

    # Rejection of invalid PEM structure
    with pytest.raises(ValueError, match="No valid '-----BEGIN CERTIFICATE-----'"):
        parse_and_validate_pem_certificate("invalid text without headers")

    # Rejection of non-DER sequence
    non_der = bytes([0x04, 0x20]) + b"\x00" * 32 # tag 0x04 (OCTET STRING) instead of 0x30 (SEQUENCE)
    non_der_b64 = base64.b64encode(non_der).decode("ascii")
    bad_pem = f"-----BEGIN CERTIFICATE-----\n{non_der_b64}\n-----END CERTIFICATE-----"
    with pytest.raises(ValueError, match="not a valid ASN.1 DER sequence"):
        parse_and_validate_pem_certificate(bad_pem)
