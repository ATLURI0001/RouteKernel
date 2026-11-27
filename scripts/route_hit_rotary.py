"""route_hit_rotary.py – bounded ring buffer for route hit counts."""
from collections import deque


class RouteHitRotary:
    def __init__(self, max_size: int = 10):
        self._buf: deque = deque(maxlen=max_size)

    def push(self, route: str) -> None:
        self._buf.append(route)

    def count(self) -> int:
        return len(self._buf)
