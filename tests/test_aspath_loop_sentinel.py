"""Tests for aspath_loop_sentinel."""
import pytest
from scripts.aspath_loop_sentinel import assert_acyclic_as_path


def test_aspath_loop_sentinel():
    assert_acyclic_as_path([65001, 65002], 65000)
    with pytest.raises(ValueError):
        assert_acyclic_as_path([65001, 65000], 65000)
