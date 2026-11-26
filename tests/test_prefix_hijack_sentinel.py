"""Tests for prefix_hijack_sentinel."""
import pytest
from scripts.prefix_hijack_sentinel import assert_authorized_origin


def test_prefix_hijack_sentinel():
    roa = {"192.0.2.0/24": {64512}}
    assert_authorized_origin("192.0.2.0/24", 64512, roa)
    with pytest.raises(ValueError):
        assert_authorized_origin("192.0.2.0/24", 64513, roa)
