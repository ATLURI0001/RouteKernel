import pytest
from scripts.as_path_loop_guard import (
    ASPathLoopGuard,
    ASPathStatus,
    ASPathViolationCode,
    is_private_asn,
    is_bogon_or_reserved_asn,
)


def test_private_and_bogon_asn_helpers():
    assert is_private_asn(64512) is True
    assert is_private_asn(65534) is True
    assert is_private_asn(4200000000) is True
    assert is_private_asn(15169) is False  # Google ASN

    assert is_bogon_or_reserved_asn(0) is True
    assert is_bogon_or_reserved_asn(23456) is True  # AS_TRANS
    assert is_bogon_or_reserved_asn(65535) is True
    assert is_bogon_or_reserved_asn(4294967295) is True
    assert is_bogon_or_reserved_asn(13335) is False  # Cloudflare ASN


def test_as_path_valid_route_accepted():
    guard = ASPathLoopGuard(local_asn=65000, allow_private_asn=True)
    verdict = guard.evaluate_route("198.51.100.0/24", [15169, 13335, 2914], peer_asn=15169)
    assert verdict.status == ASPathStatus.ACCEPTED
    assert verdict.violation_code is None
    assert verdict.violating_asn is None


def test_as_path_loop_detection():
    local_asn = 65001
    guard = ASPathLoopGuard(local_asn=local_asn, allow_private_asn=True)

    # Local ASN in middle of path
    verdict = guard.evaluate_route("203.0.113.0/24", [15169, local_asn, 2914], peer_asn=15169)
    assert verdict.status == ASPathStatus.REJECTED
    assert verdict.violation_code == ASPathViolationCode.LOOP_DETECTED
    assert verdict.violating_asn == local_asn

    # Local ASN at origin
    verdict2 = guard.evaluate_route("203.0.113.0/24", [15169, 13335, local_asn], peer_asn=15169)
    assert verdict2.status == ASPathStatus.REJECTED
    assert verdict2.violation_code == ASPathViolationCode.LOOP_DETECTED


def test_as_path_max_length_exceeded():
    guard = ASPathLoopGuard(local_asn=65000, max_path_length=5, allow_private_asn=True)
    long_path = [100, 200, 300, 400, 500, 600]
    verdict = guard.evaluate_route("192.0.2.0/24", long_path, peer_asn=100)
    assert verdict.status == ASPathStatus.REJECTED
    assert verdict.violation_code == ASPathViolationCode.MAX_LENGTH_EXCEEDED


def test_as_path_excessive_prepending():
    guard = ASPathLoopGuard(local_asn=65000, max_prepending=3, allow_private_asn=True)
    # 4 consecutive prepends of ASN 15169
    stuffed_path = [15169, 15169, 15169, 15169, 2914]
    verdict = guard.evaluate_route("198.51.100.0/24", stuffed_path, peer_asn=15169)
    assert verdict.status == ASPathStatus.REJECTED
    assert verdict.violation_code == ASPathViolationCode.EXCESSIVE_PREPENDING
    assert verdict.violating_asn == 15169


def test_as_path_bogon_and_reserved_asn():
    guard = ASPathLoopGuard(local_asn=65000, allow_private_asn=True)

    # Path containing AS_TRANS (23456)
    verdict1 = guard.evaluate_route("198.51.100.0/24", [15169, 23456, 13335], peer_asn=15169)
    assert verdict1.status == ASPathStatus.REJECTED
    assert verdict1.violation_code == ASPathViolationCode.BOGON_ASN
    assert verdict1.violating_asn == 23456

    # Path containing ASN 0
    verdict2 = guard.evaluate_route("198.51.100.0/24", [15169, 0], peer_asn=15169)
    assert verdict2.status == ASPathStatus.REJECTED
    assert verdict2.violation_code == ASPathViolationCode.BOGON_ASN
    assert verdict2.violating_asn == 0


def test_as_path_private_asn_leak_rejection():
    # Public eBGP mode (allow_private_asn=False)
    guard = ASPathLoopGuard(local_asn=15169, allow_private_asn=False)

    verdict = guard.evaluate_route("198.51.100.0/24", [13335, 64512, 2914], peer_asn=13335)
    assert verdict.status == ASPathStatus.REJECTED
    assert verdict.violation_code == ASPathViolationCode.PRIVATE_ASN_LEAK
    assert verdict.violating_asn == 64512


def test_as_path_malformed_path_rejection():
    guard = ASPathLoopGuard(local_asn=65000)

    # Empty list
    v1 = guard.evaluate_route("198.51.100.0/24", [], peer_asn=15169)
    assert v1.status == ASPathStatus.REJECTED
    assert v1.violation_code == ASPathViolationCode.MALFORMED_PATH

    # Non-integer element
    v2 = guard.evaluate_route("198.51.100.0/24", [15169, "bad_asn"], peer_asn=15169)  # type: ignore
    assert v2.status == ASPathStatus.REJECTED
    assert v2.violation_code == ASPathViolationCode.MALFORMED_PATH


def test_as_path_quarantine_capacity_and_telemetry():
    guard = ASPathLoopGuard(local_asn=65000, quarantine_capacity=2)

    # Reject 3 routes
    guard.evaluate_route("1.0.0.0/24", [65000], peer_asn=100)  # Loop
    guard.evaluate_route("2.0.0.0/24", [0], peer_asn=100)      # Bogon
    guard.evaluate_route("3.0.0.0/24", [], peer_asn=100)       # Malformed

    quarantine = guard.get_quarantined_routes()
    assert len(quarantine) == 2  # Capacity bounded at 2
    assert quarantine[0].prefix == "2.0.0.0/24"
    assert quarantine[1].prefix == "3.0.0.0/24"

    summary = guard.get_telemetry_summary()
    assert summary["quarantined_count"] == 2
    assert summary["stats"]["total_evaluated"] == 3
    assert summary["stats"]["total_rejected"] == 3
    assert summary["stats"]["ERR_AS_PATH_LOOP"] == 1
    assert summary["stats"]["ERR_BOGON_OR_RESERVED_ASN"] == 1
    assert summary["stats"]["ERR_MALFORMED_AS_PATH"] == 1

    guard.clear_quarantine()
    assert len(guard.get_quarantined_routes()) == 0
