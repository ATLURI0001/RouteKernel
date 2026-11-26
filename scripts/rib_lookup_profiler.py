"""RIB prefix lookup throughput profiler."""
import time


def benchmark_rib_lookup(rib: dict[str, str], prefixes: list[str], iterations: int = 500) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        for p in prefixes:
            _ = rib.get(p)
    elapsed = max(time.perf_counter() - start, 1e-9)
    return round((iterations * len(prefixes)) / elapsed, 2)
