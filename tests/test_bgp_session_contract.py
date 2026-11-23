import pytest
from scripts.bgp_session_contract import (
    validate_and_sanitize_bgp_session,
    BGPSessionContractError,
    is_valid_asn,
)


def test_bgp_session_valid_ebgp():
    raw = {
        "version": "routekernel/v1",
        "session_id": "session-peer-transit-level3",
        "peer_asn": 3356,
        "local_asn": 64500,
        "peer_ip": "198.51.100.1",
        "peer_type": "ebgp",
        "hold_time_sec": 90,
        "keepalive_sec": 30,
        "max_prefixes": 25000,
        "md5_password": "StrongBGPPassword2026!",
        "allowed_prefix_filters": ["198.51.100.0/24", "203.0.113.0/24"],
        "metadata": {"rack": "dc1-tor-01"},
    }

    session = validate_and_sanitize_bgp_session(raw)
    assert session.version == "routekernel/v1"
    assert session.session_id == "session-peer-transit-level3"
    assert session.peer_asn == 3356
    assert session.local_asn == 64500
    assert session.peer_ip == "198.51.100.1"
    assert session.peer_type == "ebgp"
    assert session.hold_time_sec == 90
    assert session.keepalive_sec == 30
    assert session.max_prefixes == 25000
    assert session.enable_md5_auth is True
    assert len(session.md5_secret_hash) == 64
    assert len(session.allowed_prefix_filters) == 2


def test_bgp_session_valid_ibgp():
    raw = {
        "session_id": "ibgp-core-mesh-01",
        "peer_asn": 65001,
        "local_asn": 65001,
        "peer_ip": "192.0.2.1",
        "peer_type": "ibgp",
        "hold_time_sec": 180,
    }

    session = validate_and_sanitize_bgp_session(raw)
    assert session.peer_type == "ibgp"
    assert session.keepalive_sec == 60  # Default hold_time // 3


def test_bgp_session_asn_rules():
    assert is_valid_asn(65000, allow_private=True) is True
    assert is_valid_asn(65000, allow_private=False) is False
    assert is_valid_asn(23456) is False  # AS_TRANS
    assert is_valid_asn(0) is False
    assert is_valid_asn(4294967295) is False

    # Disallowed private ASN in public peering
    raw = {
        "session_id": "public-peer",
        "peer_asn": 64512,
        "local_asn": 15169,
        "peer_ip": "198.51.100.2",
    }
    with pytest.raises(BGPSessionContractError) as exc:
        validate_and_sanitize_bgp_session(raw, options={"allow_private_asn": False})
    assert exc.value.code == "ERR_INVALID_ASN"


def test_bgp_session_peer_type_mismatch():
    # iBGP but ASNs differ
    raw = {
        "session_id": "mismatched-session",
        "peer_asn": 1234,
        "local_asn": 5678,
        "peer_ip": "198.51.100.1",
        "peer_type": "ibgp",
    }
    with pytest.raises(BGPSessionContractError) as exc:
        validate_and_sanitize_bgp_session(raw)
    assert exc.value.code == "ERR_PEER_TYPE_MISMATCH"


def test_bgp_session_peer_ip_guards():
    # Loopback IP
    raw = {
        "session_id": "loopback-peer",
        "peer_asn": 100,
        "local_asn": 200,
        "peer_ip": "127.0.0.1",
    }
    with pytest.raises(BGPSessionContractError) as exc:
        validate_and_sanitize_bgp_session(raw)
    assert exc.value.code == "ERR_INVALID_PEER_IP"

    # Malformed IP
    raw["peer_ip"] = "not-an-ip-address"
    with pytest.raises(BGPSessionContractError) as exc:
        validate_and_sanitize_bgp_session(raw)
    assert exc.value.code == "ERR_INVALID_PEER_IP"


def test_bgp_session_timer_invariants():
    # keepalive > hold_time / 3
    raw = {
        "session_id": "bad-timers",
        "peer_asn": 100,
        "local_asn": 200,
        "peer_ip": "198.51.100.1",
        "hold_time_sec": 30,
        "keepalive_sec": 15,  # 15 > 30/3 (10)
    }
    with pytest.raises(BGPSessionContractError) as exc:
        validate_and_sanitize_bgp_session(raw)
    assert exc.value.code == "ERR_INVALID_TIMERS"


def test_bgp_session_bogon_filtering():
    # Private RFC 1918 block in public filters
    raw = {
        "session_id": "bogon-filter-test",
        "peer_asn": 100,
        "local_asn": 200,
        "peer_ip": "198.51.100.1",
        "allowed_prefix_filters": ["10.50.0.0/16"],
    }
    with pytest.raises(BGPSessionContractError) as exc:
        validate_and_sanitize_bgp_session(raw, options={"allow_bogons": False})
    assert exc.value.code == "ERR_BOGON_PREFIX"

    # Allow bogons when explicitly requested for internal lab sessions
    session = validate_and_sanitize_bgp_session(raw, options={"allow_bogons": True})
    assert "10.50.0.0/16" in session.allowed_prefix_filters


def test_bgp_session_md5_auth_hardening():
    # Password too short
    raw = {
        "session_id": "weak-md5",
        "peer_asn": 100,
        "local_asn": 200,
        "peer_ip": "198.51.100.1",
        "enable_md5_auth": True,
        "md5_password": "short",
    }
    with pytest.raises(BGPSessionContractError) as exc:
        validate_and_sanitize_bgp_session(raw)
    assert exc.value.code == "ERR_AUTH_HARDENING"

    # Password with CRLF
    raw["md5_password"] = "ValidLengthPass\r\n"
    with pytest.raises(BGPSessionContractError) as exc:
        validate_and_sanitize_bgp_session(raw)
    assert exc.value.code == "ERR_AUTH_HARDENING"
