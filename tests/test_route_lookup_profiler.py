"""Tests for route_lookup_profiler."""
import sys
sys.path.insert(0, "scripts")
from route_lookup_profiler import RouteLookupProfiler


def test_route_lookup_profiler():
    p = RouteLookupProfiler()
    p.record(12.0); p.record(45.0)
    assert p.max_us() == 45.0
