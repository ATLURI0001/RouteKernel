"""Tests for route_latency_sentinel."""
import sys
sys.path.insert(0, "scripts")
from route_latency_sentinel import RouteLatencySentinel


def test_sentinel_detects_violation():
    s = RouteLatencySentinel(max_ms=100.0)
    assert s.check("/fast", 50.0) is True
    assert s.check("/slow", 200.0) is False
    assert s.violation_count() == 1
