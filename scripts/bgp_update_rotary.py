"""BGP route update latency telemetry rotary."""
from collections import deque


class BgpUpdateRotary:
    """Bounded ring buffer tracking BGP route update latencies in ms."""

    def __init__(self, capacity: int = 64) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._samples: deque[float] = deque(maxlen=capacity)

    def record(self, latency_ms: float) -> None:
        if latency_ms < 0:
            raise ValueError("latency_ms must be non-negative")
        self._samples.append(latency_ms)

    def summary(self) -> dict[str, float]:
        if not self._samples:
            return {"count": 0, "avg_ms": 0.0, "max_ms": 0.0}
        return {
            "count": len(self._samples),
            "avg_ms": sum(self._samples) / len(self._samples),
            "max_ms": max(self._samples),
        }
