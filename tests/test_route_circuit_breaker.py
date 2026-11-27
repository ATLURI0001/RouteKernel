import pytest
from scripts.route_circuit_breaker import RouteCircuitBreaker


def test_route_circuit_breaker():
    cb = RouteCircuitBreaker(threshold=2)
    for _ in range(2):
        try:
            cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        except ValueError:
            pass
    with pytest.raises(RuntimeError, match="route circuit open"):
        cb.call(lambda: None)
