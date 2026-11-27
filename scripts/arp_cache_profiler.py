"""ARP table lookup throughput profiler."""
import time


def benchmark_arp_lookup(table: dict[str, str], ips: list[str], iterations: int = 500) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        for ip in ips:
            _ = table.get(ip)
    elapsed = max(time.perf_counter() - start, 1e-9)
    return round((iterations * len(ips)) / elapsed, 2)
