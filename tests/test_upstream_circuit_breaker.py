"""Tests for upstream_circuit_breaker."""
import sys
sys.path.insert(0, "scripts")
from upstream_circuit_breaker import UpstreamCircuitBreaker


def test_upstream_circuit_breaker():
    cb = UpstreamCircuitBreaker(threshold=2)
    assert cb.is_open() is False
    cb.record_failure(); cb.record_failure()
    assert cb.is_open() is True
