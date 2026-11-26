"""Tests for bgp_community_contract."""
import pytest
from scripts.bgp_community_contract import validate_bgp_community


def test_bgp_community_contract():
    validate_bgp_community("65001:100")
    with pytest.raises(ValueError):
        validate_bgp_community("70000:100")
