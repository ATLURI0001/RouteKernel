import pytest
from scripts.bgp_path_contract import (
    validate_and_sanitize_path_announcement,
    migrate_bgp_path_schema,
    detect_as_loop,
    is_valid_asn,
    validate_community_string,
    BGPPathContractError,
    BGPPathAnnouncementSpec,
)


def test_valid_ipv4_announcement():
    raw = {
        "version": "routekernel/path-v2",
        "prefix": "198.51.100.0/24",
        "origin": "IGP",
        "as_path": [64500, 3356, 15169],
        "next_hop": "198.51.100.1",
        "med": 50,
        "local_preference": 120,
        "communities": ["64500:100", "NO_EXPORT"],
    }
    spec = validate_and_sanitize_path_announcement(raw)
    assert spec.version == "routekernel/path-v2"
    assert spec.normalized_prefix == "198.51.100.0/24"
    assert spec.origin == "IGP"
    assert spec.as_path == [64500, 3356, 15169]
    assert spec.origin_asn == 15169
    assert spec.peer_asn == 64500
    assert spec.next_hop == "198.51.100.1"
    assert spec.med == 50
    assert spec.local_preference == 120
    assert "65535:65281" in spec.communities
    assert "64500:100" in spec.communities
    assert spec.prepend_count == 0


def test_valid_ipv6_announcement_with_prepending():
    raw = {
        "version": "routekernel/path-v2",
        "prefix": "2001:db8::/32",
        "origin": "EGP",
        "as_path": [64500, 64500, 64500, 15169, 15169],
        "next_hop": "2001:db8::1",
        "med": 0,
        "local_preference": 100,
        "communities": ["64500:200", "64500:200"],  # duplicate deduplication
    }
    spec = validate_and_sanitize_path_announcement(raw)
    assert spec.origin_asn == 15169
    assert spec.prepend_count == 3
    assert len(spec.communities) == 1


def test_schema_migration_from_v1():
    legacy_payload = {
        "version": "routekernel/path-v1",
        "prefix": "203.0.113.0/24",
        "origin": "IGP",
        "asPath": [64512, 1299],
        "nextHop": "203.0.113.254",
        "localPref": 200,
    }
    migrated = migrate_bgp_path_schema(legacy_payload)
    assert migrated["version"] == "routekernel/path-v2"
    assert "asPath" not in migrated
    assert migrated["as_path"] == [64512, 1299]
    assert migrated["local_preference"] == 200
    assert migrated["next_hop"] == "203.0.113.254"

    # Fully validates migrated object
    spec = validate_and_sanitize_path_announcement(legacy_payload)
    assert spec.version == "routekernel/path-v2"
    assert spec.local_preference == 200
    assert spec.peer_asn == 64512


def test_as_loop_detection():
    # Consecutive prepending is valid
    has_loop, _ = detect_as_loop([64500, 64500, 3356, 15169])
    assert not has_loop

    # Non-consecutive duplicate indicates routing loop
    has_loop, looping_asn = detect_as_loop([64500, 3356, 15169, 64500])
    assert has_loop
    assert looping_asn == 64500

    raw = {
        "prefix": "198.51.100.0/24",
        "origin": "IGP",
        "as_path": [64500, 3356, 15169, 64500],
        "next_hop": "198.51.100.1",
    }
    with pytest.raises(BGPPathContractError) as exc_info:
        validate_and_sanitize_path_announcement(raw)
    assert exc_info.value.code == "AS_LOOP_DETECTED"


def test_as_path_overflow_and_prepend_limit():
    raw_overflow = {
        "prefix": "198.51.100.0/24",
        "origin": "IGP",
        "as_path": [64500] * 35,
        "next_hop": "198.51.100.1",
    }
    with pytest.raises(BGPPathContractError) as exc_info:
        validate_and_sanitize_path_announcement(raw_overflow, max_path_length=32)
    assert exc_info.value.code == "AS_PATH_OVERFLOW"

    raw_excess_prepend = {
        "prefix": "198.51.100.0/24",
        "origin": "IGP",
        "as_path": [64500] * 12,
        "next_hop": "198.51.100.1",
    }
    with pytest.raises(BGPPathContractError) as exc_info:
        validate_and_sanitize_path_announcement(raw_excess_prepend, max_path_length=64)
    assert exc_info.value.code == "PREPEND_LIMIT_EXCEEDED"


def test_invalid_asn_and_disallowed_asn():
    assert not is_valid_asn(0)
    assert not is_valid_asn(23456)
    assert not is_valid_asn(4294967295)
    assert is_valid_asn(64500)

    raw_invalid_asn = {
        "prefix": "198.51.100.0/24",
        "origin": "IGP",
        "as_path": [64500, 0],
        "next_hop": "198.51.100.1",
    }
    with pytest.raises(BGPPathContractError) as exc_info:
        validate_and_sanitize_path_announcement(raw_invalid_asn)
    assert exc_info.value.code == "INVALID_ASN"

    raw_disallowed = {
        "prefix": "198.51.100.0/24",
        "origin": "IGP",
        "as_path": [64500, 701],
        "next_hop": "198.51.100.1",
    }
    with pytest.raises(BGPPathContractError) as exc_info:
        validate_and_sanitize_path_announcement(raw_disallowed, disallowed_asns={701})
    assert exc_info.value.code == "DISALLOWED_ASN"


def test_address_family_mismatch_and_invalid_nexthop():
    raw_mismatch = {
        "prefix": "198.51.100.0/24",
        "origin": "IGP",
        "as_path": [64500, 15169],
        "next_hop": "2001:db8::1",
    }
    with pytest.raises(BGPPathContractError) as exc_info:
        validate_and_sanitize_path_announcement(raw_mismatch)
    assert exc_info.value.code == "ADDRESS_FAMILY_MISMATCH"

    raw_bad_ip = {
        "prefix": "198.51.100.0/24",
        "origin": "IGP",
        "as_path": [64500, 15169],
        "next_hop": "999.999.999.999",
    }
    with pytest.raises(BGPPathContractError) as exc_info:
        validate_and_sanitize_path_announcement(raw_bad_ip)
    assert exc_info.value.code == "INVALID_NEXT_HOP"


def test_community_validation():
    assert validate_community_string("NO_EXPORT") == "65535:65281"
    assert validate_community_string("64500:100") == "64500:100"
    assert validate_community_string("64500:100:200") == "64500:100:200"

    with pytest.raises(BGPPathContractError) as exc_info:
        validate_community_string("invalid-format")
    assert exc_info.value.code == "INVALID_COMMUNITY"
