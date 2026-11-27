"""Tests for BgpFlapRotary."""
from scripts.bgp_flap_rotary import BgpFlapRotary


def test_bgp_flap_rotary():
    r = BgpFlapRotary(capacity=2)
    r.record(1)
    r.record(3)
    r.record(5)
    assert r.avg_flaps() == 4.0
