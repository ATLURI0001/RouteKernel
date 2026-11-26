"""Tests for PeerSessionCircuitBreaker."""
import pytest
from scripts.peer_session_circuit_breaker import PeerCircuitOpenError, PeerSessionCircuitBreaker


def test_peer_circuit_opens():
    cb = PeerSessionCircuitBreaker(threshold=2, cooldown_s=5.0)
    with pytest.raises(OSError):
        cb.call(lambda: (_ for _ in ()).throw(OSError("reset")))
    with pytest.raises(OSError):
        cb.call(lambda: (_ for _ in ()).throw(OSError("reset")))
    with pytest.raises(PeerCircuitOpenError):
        cb.call(lambda: "ok")
