"""Tests for route_hit_rotary."""
import sys
sys.path.insert(0, "scripts")
from route_hit_rotary import RouteHitRotary


def test_route_hit_rotary():
    r = RouteHitRotary(max_size=2)
    r.push("/a"); r.push("/b"); r.push("/c")
    assert r.count() == 2
