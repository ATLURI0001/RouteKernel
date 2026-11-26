"""
Unit tests for RPKI Fallback Circuit Breaker.
"""

import pytest

from scripts.rpki_fallback_circuit_breaker import (
    CircuitState,
    FallbackPolicy,
    RPKIFallbackCircuitBreaker,
    RPKIFallbackResult,
    RPKIRouteAnnouncement,
    RPKIValidationState,
)


def test_nominal_closed_state_routing():
    def mock_primary(r: RPKIRouteAnnouncement) -> RPKIValidationState:
        return RPKIValidationState.VALID

    cb = RPKIFallbackCircuitBreaker(failure_threshold=3, primary_validator=mock_primary)
    route = RPKIRouteAnnouncement(prefix="198.51.100.0/24", origin_as=64500, peer_ip="192.0.2.1")

    res = cb.evaluate_route(route)
    assert res.routed is True
    assert res.circuit_state == CircuitState.CLOSED
    assert res.validation_state == RPKIValidationState.VALID
    assert res.fallback_engaged is False


def test_legitimate_invalid_dropped_without_tripping():
    def mock_primary(r: RPKIRouteAnnouncement) -> RPKIValidationState:
        return RPKIValidationState.INVALID

    cb = RPKIFallbackCircuitBreaker(failure_threshold=3, primary_validator=mock_primary)
    route = RPKIRouteAnnouncement(prefix="203.0.113.0/24", origin_as=64510, peer_ip="192.0.2.2")

    # INVALID routes should be dropped, but they are NOT validator errors, so circuit stays CLOSED
    for _ in range(5):
        res = cb.evaluate_route(route)
        assert res.routed is False
        assert res.circuit_state == CircuitState.CLOSED
        assert res.validation_state == RPKIValidationState.INVALID
        assert res.fallback_engaged is False

    assert cb.trip_count == 0


def test_circuit_trips_to_open_on_validator_failures():
    def failing_primary(r: RPKIRouteAnnouncement) -> RPKIValidationState:
        raise ConnectionResetError("RTR daemon connection reset by peer")

    cb = RPKIFallbackCircuitBreaker(
        failure_threshold=3,
        recovery_timeout_sec=10.0,
        primary_validator=failing_primary,
    )
    route = RPKIRouteAnnouncement(prefix="198.51.100.0/24", origin_as=64500, peer_ip="192.0.2.1")

    # First 2 failures: circuit remains CLOSED, fallback engaged
    res1 = cb.evaluate_route(route, now=100.0)
    assert res1.circuit_state == CircuitState.CLOSED
    assert res1.fallback_engaged is True

    res2 = cb.evaluate_route(route, now=101.0)
    assert res2.circuit_state == CircuitState.CLOSED

    # 3rd failure: trips to OPEN!
    res3 = cb.evaluate_route(route, now=102.0)
    assert res3.circuit_state == CircuitState.OPEN
    assert cb.state == CircuitState.OPEN
    assert cb.trip_count == 1


def test_secondary_rtr_fallback_routing():
    def failing_primary(r: RPKIRouteAnnouncement) -> RPKIValidationState:
        raise TimeoutError("RTR timeout")

    def secondary_validator(r: RPKIRouteAnnouncement) -> RPKIValidationState:
        return RPKIValidationState.VALID

    cb = RPKIFallbackCircuitBreaker(
        failure_threshold=1,
        recovery_timeout_sec=30.0,
        primary_validator=failing_primary,
        secondary_validator=secondary_validator,
    )
    route = RPKIRouteAnnouncement(prefix="192.0.2.0/24", origin_as=65001, peer_ip="192.0.2.5")

    res = cb.evaluate_route(route, now=100.0)
    assert res.circuit_state == CircuitState.OPEN
    assert res.policy_applied == FallbackPolicy.FALLBACK_SECONDARY_RTR
    assert res.routed is True
    assert res.fallback_engaged is True


def test_half_open_recovery_and_retrip():
    call_count = 0

    def recovering_primary(r: RPKIRouteAnnouncement) -> RPKIValidationState:
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            return RPKIValidationState.VALIDATOR_ERROR
        return RPKIValidationState.VALID

    cb = RPKIFallbackCircuitBreaker(
        failure_threshold=2,
        recovery_timeout_sec=20.0,
        half_open_success_threshold=2,
        primary_validator=recovering_primary,
    )
    route = RPKIRouteAnnouncement(prefix="10.0.0.0/8", origin_as=65000, peer_ip="10.0.0.1")

    # Trip to OPEN
    cb.evaluate_route(route, now=100.0)
    cb.evaluate_route(route, now=101.0)
    assert cb.state == CircuitState.OPEN

    # Step before timeout -> still OPEN
    cb.evaluate_route(route, now=115.0)
    assert cb.state == CircuitState.OPEN

    # Step after timeout (now=125.0) -> transitions to HALF_OPEN, succeeds 1st probe
    res_half1 = cb.evaluate_route(route, now=125.0)
    assert res_half1.circuit_state == CircuitState.HALF_OPEN

    # 2nd success in HALF_OPEN -> transitions back to CLOSED!
    res_half2 = cb.evaluate_route(route, now=126.0)
    assert cb.state == CircuitState.CLOSED


def test_validation_input_bounds():
    with pytest.raises(ValueError):
        RPKIFallbackCircuitBreaker(failure_threshold=0)
    with pytest.raises(ValueError):
        RPKIFallbackCircuitBreaker(recovery_timeout_sec=0)
    with pytest.raises(ValueError):
        RPKIFallbackCircuitBreaker(half_open_success_threshold=0)


def test_metrics_and_reset():
    cb = RPKIFallbackCircuitBreaker(failure_threshold=5)
    metrics = cb.get_metrics()
    assert metrics["state"] == "CLOSED"
    assert metrics["total_evaluated"] == 0

    cb.reset()
    assert cb.state == CircuitState.CLOSED
