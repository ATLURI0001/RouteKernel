"""IPv4 Longest Prefix Match (LPM) Radix Trie Benchmark Profiler.

Benchmarks O(32) bitwise radix tree lookups vs linear prefix scanning
across routing table lookups.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


class TrieNode:
    __slots__ = ("children", "next_hop")

    def __init__(self) -> None:
        self.children: List[Optional[TrieNode]] = [None, None]
        self.next_hop: Optional[str] = None


@dataclass
class LpmBenchmarkResult:
    route_count: int
    lookup_count: int
    p50_microseconds: float
    p90_microseconds: float
    throughput_lookups_sec: float


class LpmTrieProfiler:
    """Radix-tree LPM router table and microbenchmark profiler."""

    def __init__(self) -> None:
        self.root = TrieNode()
        self.route_count = 0

    def insert(self, cidr: str, next_hop: str) -> None:
        net = ipaddress.IPv4Network(cidr, strict=False)
        ip_int = int(net.network_address)
        prefix_len = net.prefixlen

        node = self.root
        for i in range(prefix_len):
            bit = (ip_int >> (31 - i)) & 1
            if node.children[bit] is None:
                node.children[bit] = TrieNode()
            node = node.children[bit]  # type: ignore
        node.next_hop = next_hop
        self.route_count += 1

    def lookup(self, ip_str: str) -> Optional[str]:
        ip_int = int(ipaddress.IPv4Address(ip_str))
        node: Optional[TrieNode] = self.root
        best_match: Optional[str] = node.next_hop

        for i in range(32):
            if node is None:
                break
            if node.next_hop is not None:
                best_match = node.next_hop
            bit = (ip_int >> (31 - i)) & 1
            node = node.children[bit]

        if node is not None and node.next_hop is not None:
            best_match = node.next_hop
        return best_match

    def run_benchmark(self, ips: List[str], iterations: int = 30) -> LpmBenchmarkResult:
        latencies: List[float] = []
        t_start = time.perf_counter()

        for _ in range(iterations):
            start = time.perf_counter()
            for ip in ips:
                self.lookup(ip)
            latencies.append((time.perf_counter() - start) * 1_000_000.0 / len(ips))

        total_sec = time.perf_counter() - t_start
        latencies.sort()

        return LpmBenchmarkResult(
            route_count=self.route_count,
            lookup_count=len(ips) * iterations,
            p50_microseconds=round(latencies[int(len(latencies) * 0.5)], 3),
            p90_microseconds=round(latencies[int(len(latencies) * 0.9)], 3),
            throughput_lookups_sec=round((len(ips) * iterations) / max(1e-6, total_sec), 1),
        )
