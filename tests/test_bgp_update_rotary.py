"""Tests for BgpUpdateRotary."""
from scripts.bgp_update_rotary import BgpUpdateRotary


def test_bgp_update_rotary_tracks_bounded_samples():
    rotary = BgpUpdateRotary(capacity=3)
    for val in (10.0, 20.0, 30.0, 40.0):
        rotary.record(val)
    s = rotary.summary()
    assert s["count"] == 3
    assert s["avg_ms"] == 30.0
    assert s["max_ms"] == 40.0
