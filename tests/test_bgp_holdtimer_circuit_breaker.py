"""Tests for BgpHoldtimerCircuitBreaker."""
import pytest
from scripts.bgp_holdtimer_circuit_breaker import (
    BgpHoldtimerCircuitBreaker,
    HoldtimerCircuitOpenError,
)


def test_bgp_holdtimer_circuit_breaker():
    cb = BgpHoldtimerCircuitBreaker(threshold=2, cooldown_s=5.0)
    with pytest.raises(TimeoutError):
        cb.call(lambda: (_ for _ in ()).throw(TimeoutError("keepalive missed")))
    with pytest.raises(TimeoutError):
        cb.call(lambda: (_ for _ in ()).throw(TimeoutError("keepalive missed")))
    with pytest.raises(HoldtimerCircuitOpenError):
        cb.call(lambda: "ok")
