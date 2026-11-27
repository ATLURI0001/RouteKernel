"""route_loop_sentinel.py – sentinel for circular route redirects."""


class RouteLoopSentinel:
    def __init__(self, max_hops: int = 5):
        self.max_hops = max_hops
        self.loops = 0

    def check(self, hops: int) -> bool:
        if hops > self.max_hops:
            self.loops += 1
            return False
        return True
