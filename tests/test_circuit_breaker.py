"""
Unit tests for RouteKernel Upstream Circuit Breaker & Adaptive Health Probe Rotary.
"""

import sys
from pathlib import Path
import time
import pytest

# Ensure scripts dir is on sys.path
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from circuit_breaker import UpstreamCircuitBreaker, CircuitState, CircuitOpenError


def test_circuit_breaker_normal_closed_execution():
    cb = UpstreamCircuitBreaker(failure_threshold=3, recovery_timeout_sec=0.1)
    assert cb.state == CircuitState.CLOSED

    # Successful call
    result = cb.execute(lambda x, y: x + y, 10, 20)
    assert result == 30
    assert cb.state == CircuitState.CLOSED
    assert cb.get_telemetry()["consecutive_failures"] == 0


def test_circuit_breaker_trips_to_open_on_failures():
    cb = UpstreamCircuitBreaker(failure_threshold=3, recovery_timeout_sec=0.2)

    def failing_call():
        raise RuntimeError("upstream timeout")

    # 1st failure
    with pytest.raises(RuntimeError):
        cb.execute(failing_call)
    assert cb.state == CircuitState.CLOSED

    # 2nd failure
    with pytest.raises(RuntimeError):
        cb.execute(failing_call)
    assert cb.state == CircuitState.CLOSED

    # 3rd failure: trips to OPEN!
    with pytest.raises(RuntimeError):
        cb.execute(failing_call)
    assert cb.state == CircuitState.OPEN
    assert cb.get_telemetry()["trip_count"] == 1

    # 4th call is rejected immediately with CircuitOpenError without invoking target
    with pytest.raises(CircuitOpenError) as exc_info:
        cb.execute(lambda: "should not run")
    assert exc_info.value.cooldown_remaining_sec > 0


def test_circuit_breaker_half_open_recovery():
    # Short cooldown for test speed
    cb = UpstreamCircuitBreaker(
        failure_threshold=2,
        recovery_timeout_sec=0.05,
        canary_success_threshold=2,
    )

    def failing_call():
        raise ValueError("error")

    # Trip to OPEN
    for _ in range(2):
        with pytest.raises(ValueError):
            cb.execute(failing_call)
    assert cb.state == CircuitState.OPEN

    # Sleep past recovery cooldown
    time.sleep(0.06)

    # State transitions to HALF_OPEN
    assert cb.state == CircuitState.HALF_OPEN

    # 1st canary probe succeeds
    cb.execute(lambda: "ok1")
    assert cb.state == CircuitState.HALF_OPEN

    # 2nd canary probe succeeds: resets to CLOSED
    cb.execute(lambda: "ok2")
    assert cb.state == CircuitState.CLOSED
    assert cb.get_telemetry()["consecutive_failures"] == 0


def test_circuit_breaker_half_open_failure_backoff():
    cb = UpstreamCircuitBreaker(
        failure_threshold=2,
        recovery_timeout_sec=0.05,
        canary_success_threshold=2,
        backoff_multiplier=2.0,
    )

    # Trip to OPEN
    for _ in range(2):
        with pytest.raises(ZeroDivisionError):
            cb.execute(lambda: 1 / 0)
    assert cb.state == CircuitState.OPEN

    # Wait for cooldown to expire
    time.sleep(0.06)
    assert cb.state == CircuitState.HALF_OPEN

    # Canary probe fails: trips back to OPEN with doubled cooldown (0.10s)
    with pytest.raises(ZeroDivisionError):
        cb.execute(lambda: 1 / 0)

    assert cb.state == CircuitState.OPEN
    assert cb.get_telemetry()["current_recovery_timeout_sec"] == 0.10
    assert cb.get_telemetry()["trip_count"] == 2
