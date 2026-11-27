"""Tests for next_hop_contract."""
import pytest
from scripts.next_hop_contract import validate_next_hop


def test_next_hop_contract():
    validate_next_hop("192.0.2.1")
    with pytest.raises(ValueError):
        validate_next_hop("0.0.0.0")
