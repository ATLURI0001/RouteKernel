"""RouteKernel: waypoint contract – validates waypoint dicts."""


def validate_waypoint(wp: dict) -> None:
    if not isinstance(wp, dict):
        raise TypeError("waypoint must be a dict")
    if "lat" not in wp or "lng" not in wp:
        raise ValueError("waypoint missing lat or lng")
    if not (-90 <= wp["lat"] <= 90) or not (-180 <= wp["lng"] <= 180):
        raise ValueError("waypoint coordinates out of range")
