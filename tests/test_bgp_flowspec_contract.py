"""
Tests for BGP Flowspec (RFC 8955 / RFC 8956) Policy Contract.
"""

import pytest
from scripts.bgp_flowspec_contract import (
    FlowspecContractError,
    FlowspecContractValidator,
    FlowspecRule,
    PortCondition,
)


def test_valid_discard_flowspec_rule() -> None:
    validator = FlowspecContractValidator()
    raw = {
        "rule_id": "rule-ddos-drop-syn-flood",
        "schema_version": "flowspec/v1",
        "destination_prefix": "198.51.100.0/24",
        "source_prefix": "203.0.113.0/24",
        "ip_protocols": ["tcp"],
        "destination_ports": [80, 443],
        "action_type": "DISCARD",
    }
    result = validator.validate_rule(raw)
    assert result.is_valid is True
    assert result.violations == []
    rule = result.normalized_rule
    assert rule is not None
    assert rule.destination_prefix == "198.51.100.0/24"
    assert rule.ip_protocols == [6]
    assert len(rule.destination_ports) == 2
    assert rule.action_type == "DISCARD"


def test_rate_limit_action_and_dscp_mark() -> None:
    validator = FlowspecContractValidator()
    raw_rate = {
        "rule_id": "rule-rate-limit-udp",
        "schema_version": "flowspec/v2",
        "destination_prefix": "198.51.100.50/32",
        "ip_protocols": ["udp", 17],
        "destination_ports": [(">", 1024)],
        "action_type": "RATE_LIMIT",
        "rate_limit_bps": 5000000.0,
    }
    res_rate = validator.validate_rule(raw_rate)
    assert res_rate.is_valid is True
    assert res_rate.normalized_rule.rate_limit_bps == 5000000.0

    raw_dscp = {
        "rule_id": "rule-mark-scavenger",
        "schema_version": "flowspec/v1",
        "source_prefix": "10.0.0.0/8",
        "action_type": "MARK_DSCP",
        "dscp_mark": 46,  # Expedited Forwarding
    }
    res_dscp = validator.validate_rule(raw_dscp)
    assert res_dscp.is_valid is True
    assert res_dscp.normalized_rule.dscp_mark == 46


def test_redirect_vrf_validation() -> None:
    validator = FlowspecContractValidator()
    raw = {
        "rule_id": "rule-scrubbing-redirect",
        "schema_version": "flowspec/v1",
        "destination_prefix": "192.0.2.1/32",
        "action_type": "REDIRECT_VRF",
        "redirect_target": "65001:100",
    }
    res = validator.validate_rule(raw)
    assert res.is_valid is True
    assert res.normalized_rule.redirect_target == "65001:100"

    # Invalid route target format
    raw_bad = dict(raw, redirect_target="not-a-route-target")
    res_bad = validator.validate_rule(raw_bad)
    assert res_bad.is_valid is False
    assert any("must conform to ASN:index" in v for v in res_bad.violations)


def test_invariant_rejections_and_boundaries() -> None:
    validator = FlowspecContractValidator()

    # Neither dest nor src specified
    res_no_prefix = validator.validate_rule({
        "rule_id": "rule-no-prefix",
        "schema_version": "flowspec/v1",
        "action_type": "DISCARD",
    })
    assert res_no_prefix.is_valid is False
    assert any("At least one of 'destination_prefix' or 'source_prefix'" in v for v in res_no_prefix.violations)

    # IPv4 / IPv6 mismatch
    res_family_mismatch = validator.validate_rule({
        "rule_id": "rule-mismatch",
        "schema_version": "flowspec/v1",
        "destination_prefix": "192.0.2.0/24",
        "source_prefix": "2001:db8::/32",
        "action_type": "DISCARD",
    })
    assert res_family_mismatch.is_valid is False
    assert any("Address family mismatch" in v for v in res_family_mismatch.violations)

    # Port out of bounds
    res_bad_port = validator.validate_rule({
        "rule_id": "rule-bad-port",
        "schema_version": "flowspec/v1",
        "destination_prefix": "192.0.2.0/24",
        "destination_ports": [70000],
        "action_type": "DISCARD",
    })
    assert res_bad_port.is_valid is False
    assert any("out of valid range" in v for v in res_bad_port.violations)


def test_batch_capacity_enforcement() -> None:
    validator = FlowspecContractValidator(max_batch_size=5)
    rules = [
        {
            "rule_id": f"rule-{i}",
            "schema_version": "flowspec/v1",
            "destination_prefix": f"192.0.2.{i}/32",
            "action_type": "DISCARD",
        }
        for i in range(6)
    ]

    with pytest.raises(FlowspecContractError) as exc_info:
        validator.enforce_batch(rules)

    assert exc_info.value.code == "BATCH_CAPACITY_EXCEEDED"
