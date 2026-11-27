"""Tests for route_loop_sentinel."""
import sys
sys.path.insert(0, "scripts")
from route_loop_sentinel import RouteLoopSentinel


def test_route_loop_sentinel():
    s = RouteLoopSentinel(max_hops=3)
    assert s.check(2) is True
    assert s.check(5) is False
    assert s.loops == 1
