"""Unit tests for RouteFlapDamper and RFC 2439 oscillation suppression."""

from __future__ import annotations

import pytest
from scripts.flap_damper import FlapDampingConfig, RouteFlapDamper, UpstreamState


def test_flap_damping_config_validation() -> None:
    # Valid config
    cfg = FlapDampingConfig(penalty_per_flap=500.0, half_life_seconds=10.0, suppress_threshold=1500.0, reuse_threshold=500.0)
    assert cfg.penalty_per_flap == 500.0

    # Invalid thresholds (suppress <= reuse)
    with pytest.raises(ValueError, match="strictly greater"):
        FlapDampingConfig(suppress_threshold=500.0, reuse_threshold=500.0)

    # Invalid penalty
    with pytest.raises(ValueError, match="penalty_per_flap"):
        FlapDampingConfig(penalty_per_flap=-10.0)


def test_flap_damping_stable_upstream() -> None:
    damper = RouteFlapDamper()
    assert damper.is_routable("api-1") is True

    # Reporting same healthy state causes no flap penalty
    state = damper.record_state_change("api-1", True, timestamp=1000.0)
    assert state == UpstreamState.HEALTHY

    status = damper.get_upstream_status("api-1", timestamp=1000.0)
    assert status["penalty"] == 0.0
    assert status["total_flaps"] == 0
    assert status["routable"] is True


def test_flap_damping_escalation_to_suppressed() -> None:
    cfg = FlapDampingConfig(
        penalty_per_flap=1100.0,
        half_life_seconds=20.0,
        suppress_threshold=2000.0,
        reuse_threshold=500.0,
    )
    damper = RouteFlapDamper(cfg)
    t = 1000.0

    # First flap: True -> False (+1100 penalty)
    state = damper.record_state_change("db-primary", False, timestamp=t)
    assert state == UpstreamState.FLAPPING
    assert damper.is_routable("db-primary", timestamp=t) is False  # unhealthy

    # Second flap: False -> True (+1100 penalty, total > 2000 >= suppress_threshold)
    t += 1.0
    state = damper.record_state_change("db-primary", True, timestamp=t)
    assert state == UpstreamState.SUPPRESSED

    # Even though health is True, suppression blocks routing!
    assert damper.is_routable("db-primary", timestamp=t) is False
    status = damper.get_upstream_status("db-primary", timestamp=t)
    assert status["suppressed"] is True
    assert status["total_flaps"] == 2


def test_flap_damping_exponential_decay_and_reuse() -> None:
    cfg = FlapDampingConfig(
        penalty_per_flap=1200.0,
        half_life_seconds=10.0,
        suppress_threshold=2000.0,
        reuse_threshold=600.0,
        max_suppress_seconds=100.0,
    )
    damper = RouteFlapDamper(cfg)
    t = 1000.0

    # Suppress upstream with 2 rapid flaps (>2000 penalty)
    damper.record_state_change("srv-1", False, timestamp=t)
    t += 1.0
    damper.record_state_change("srv-1", True, timestamp=t)
    assert damper.get_upstream_status("srv-1", timestamp=t)["suppressed"] is True

    # Advance 10 seconds (1 half-life): penalty decays from ~2319 to ~1160
    t += 10.0
    status = damper.get_upstream_status("srv-1", timestamp=t)
    assert 1050.0 < status["penalty"] < 1250.0
    assert status["suppressed"] is True  # still > reuse_threshold (600)

    # Advance another 10 seconds (2 half-lives total): penalty decays from ~1000 to ~500 (< 600 reuse_threshold)
    t += 10.0
    status = damper.get_upstream_status("srv-1", timestamp=t)
    assert status["penalty"] < 600.0
    assert status["suppressed"] is False
    assert status["routable"] is True


def test_flap_damping_max_suppress_timeout() -> None:
    cfg = FlapDampingConfig(
        penalty_per_flap=2000.0,
        half_life_seconds=100.0,
        suppress_threshold=2000.0,
        reuse_threshold=500.0,
        max_suppress_seconds=30.0,
    )
    damper = RouteFlapDamper(cfg)
    t = 1000.0

    damper.record_state_change("payment-gw", False, timestamp=t)
    t += 1.0
    damper.record_state_change("payment-gw", True, timestamp=t)
    assert damper.get_upstream_status("payment-gw", timestamp=t)["suppressed"] is True

    # Advance 35 seconds (exceeding max_suppress_seconds=30)
    t += 35.0
    status = damper.get_upstream_status("payment-gw", timestamp=t)
    assert status["suppressed"] is False
    assert status["routable"] is True


def test_flap_damping_reset() -> None:
    damper = RouteFlapDamper()
    damper.record_state_change("redis-1", False, timestamp=1000.0)
    assert damper.get_upstream_status("redis-1")["total_flaps"] == 1

    damper.reset("redis-1")
    assert damper.get_upstream_status("redis-1")["total_flaps"] == 0
