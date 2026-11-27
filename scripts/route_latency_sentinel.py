"""route_latency_sentinel.py – sentinel for route latency threshold violations."""


class RouteLatencySentinel:
    def __init__(self, max_ms: float):
        self.max_ms = max_ms
        self.violations: list[str] = []

    def check(self, route: str, latency_ms: float) -> bool:
        if latency_ms > self.max_ms:
            self.violations.append(route)
            return False
        return True

    def violation_count(self) -> int:
        return len(self.violations)
