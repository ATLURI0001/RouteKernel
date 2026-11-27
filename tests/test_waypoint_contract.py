import pytest
from scripts.waypoint_contract import validate_waypoint


def test_waypoint_contract():
    validate_waypoint({"lat": 51.5, "lng": -0.1})
    with pytest.raises(ValueError, match="missing lat"):
        validate_waypoint({"lat": 10})
