"""route_lookup_profiler.py – tracks route table lookup durations."""


class RouteLookupProfiler:
    def __init__(self):
        self._samples: list[float] = []

    def record(self, us: float) -> None:
        self._samples.append(us)

    def max_us(self) -> float:
        return max(self._samples) if self._samples else 0.0
