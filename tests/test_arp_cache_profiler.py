"""Tests for arp_cache_profiler."""
from scripts.arp_cache_profiler import benchmark_arp_lookup


def test_arp_cache_profiler():
    ops = benchmark_arp_lookup({"10.0.0.1": "aa:bb:cc:dd:ee:ff"}, ["10.0.0.1", "10.0.0.2"], iterations=100)
    assert ops > 0
