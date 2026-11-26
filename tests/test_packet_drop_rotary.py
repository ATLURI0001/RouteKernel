"""Tests for PacketDropRotary."""
from scripts.packet_drop_rotary import PacketDropRotary


def test_packet_drop_rotary():
    r = PacketDropRotary(capacity=2)
    r.record(2)
    r.record(4)
    r.record(8)
    assert r.avg_drops() == 6.0
