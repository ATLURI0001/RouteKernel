"""Bounded ring buffer for BGP route flap counts."""
from collections import deque


class BgpFlapRotary:
    def __init__(self, capacity: int = 32) -> None:
        self._samples: deque[int] = deque(maxlen=capacity)

    def record(self, flaps: int) -> None:
        if flaps < 0:
            raise ValueError("flaps must be non-negative")
        self._samples.append(flaps)

    def avg_flaps(self) -> float:
        return sum(self._samples) / len(self._samples) if self._samples else 0.0
