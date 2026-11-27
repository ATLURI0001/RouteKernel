"""Tests for OspfLsaCircuitBreaker."""
import pytest
from scripts.ospf_lsa_circuit_breaker import OspfCircuitOpenError, OspfLsaCircuitBreaker


def test_ospf_lsa_circuit_breaker():
    cb = OspfLsaCircuitBreaker(threshold=2, cooldown_s=5.0)
    with pytest.raises(ValueError):
        cb.call(lambda: (_ for _ in ()).throw(ValueError("bad LSA")))
    with pytest.raises(ValueError):
        cb.call(lambda: (_ for _ in ()).throw(ValueError("bad LSA")))
    with pytest.raises(OspfCircuitOpenError):
        cb.call(lambda: "ok")
