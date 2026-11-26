"""Tests for rib_lookup_profiler."""
from scripts.rib_lookup_profiler import benchmark_rib_lookup


def test_rib_lookup_profiler():
    ops = benchmark_rib_lookup({"10.0.0.0/8": "nh1"}, ["10.0.0.0/8", "192.0.2.0/24"], iterations=100)
    assert ops > 0
