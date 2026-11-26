"""Bounded ring buffer for packet drop telemetry."""
from collections import deque


class PacketDropRotary:
    def __init__(self, capacity: int = 32) -> None:
        self._samples: deque[int] = deque(maxlen=capacity)

    def record(self, drops: int) -> None:
        if drops < 0:
            raise ValueError("drops must be non-negative")
        self._samples.append(drops)

    def avg_drops(self) -> float:
        return sum(self._samples) / len(self._samples) if self._samples else 0.0
