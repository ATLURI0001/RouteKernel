"""
IPv4 Longest Prefix Match (LPM) Radix Trie Routing Engine & Benchmark Profiler.

Provides O(32) deterministic binary trie route lookups with path pruning and
comparative performance benchmarking against linear CIDR scans.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any, Iterator


@dataclass
class RouteEntry:
    cidr: str
    gateway: str
    metric: int = 100
    tag: str = ""


class _TrieNode:
    __slots__ = ("left", "right", "route")

    def __init__(self) -> None:
        self.left: _TrieNode | None = None   # bit 0
        self.right: _TrieNode | None = None  # bit 1
        self.route: RouteEntry | None = None


def ip_to_uint32(ip_str: str) -> int:
    """Convert IPv4 dotted-quad string to 32-bit unsigned integer."""
    try:
        octets = [int(x) for x in ip_str.strip().split(".")]
        if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
            raise ValueError
        return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    except Exception:
        raise ValueError(f"Invalid IPv4 address format: '{ip_str}'")


def parse_cidr(cidr_str: str) -> tuple[int, int]:
    """Parse CIDR string into (32-bit integer prefix, prefix length)."""
    parts = cidr_str.strip().split("/")
    if len(parts) == 1:
        ip_int = ip_to_uint32(parts[0])
        return ip_int, 32
    if len(parts) != 2:
        raise ValueError(f"Invalid CIDR notation: '{cidr_str}'")

    ip_int = ip_to_uint32(parts[0])
    try:
        prefix_len = int(parts[1])
        if prefix_len < 0 or prefix_len > 32:
            raise ValueError
    except ValueError:
        raise ValueError(f"Invalid CIDR mask length: '{parts[1]}'")

    # Mask out host bits to normalize network address
    mask = ((1 << 32) - 1) ^ ((1 << (32 - prefix_len)) - 1) if prefix_len < 32 else 0xFFFFFFFF
    if prefix_len == 0:
        mask = 0
    return ip_int & mask, prefix_len


class IPv4RadixTrieRouter:
    """Deterministic binary Radix Trie for O(1) Longest Prefix Match IPv4 routing."""

    def __init__(self) -> None:
        self.root = _TrieNode()
        self._count = 0

    def insert(self, cidr: str, gateway: str, metric: int = 100, tag: str = "") -> None:
        """Insert a routing entry for a given CIDR network prefix."""
        prefix_int, prefix_len = parse_cidr(cidr)
        curr = self.root

        for i in range(prefix_len):
            bit = (prefix_int >> (31 - i)) & 1
            if bit == 0:
                if curr.left is None:
                    curr.left = _TrieNode()
                curr = curr.left
            else:
                if curr.right is None:
                    curr.right = _TrieNode()
                curr = curr.right

        if curr.route is None:
            self._count += 1
        curr.route = RouteEntry(cidr=cidr, gateway=gateway, metric=metric, tag=tag)

    def lookup(self, ip_str: str) -> RouteEntry | None:
        """Find the most specific (longest prefix match) route for an IPv4 address."""
        ip_int = ip_to_uint32(ip_str)
        curr: _TrieNode | None = self.root
        best_match: RouteEntry | None = None

        if curr.route is not None:
            best_match = curr.route

        for i in range(32):
            if curr is None:
                break
            bit = (ip_int >> (31 - i)) & 1
            curr = curr.right if bit == 1 else curr.left
            if curr is not None and curr.route is not None:
                best_match = curr.route

        return best_match

    def delete(self, cidr: str) -> bool:
        """Delete a CIDR prefix and prune dead intermediate nodes."""
        prefix_int, prefix_len = parse_cidr(cidr)

        path: list[tuple[_TrieNode, int]] = []
        curr = self.root

        for i in range(prefix_len):
            bit = (prefix_int >> (31 - i)) & 1
            path.append((curr, bit))
            curr = curr.right if bit == 1 else curr.left
            if curr is None:
                return False

        if curr.route is None:
            return False

        curr.route = None
        self._count -= 1

        # Path pruning: remove intermediate branches with no children and no routes
        node = curr
        for parent, bit in reversed(path):
            if node.left is None and node.right is None and node.route is None:
                if bit == 0:
                    parent.left = None
                else:
                    parent.right = None
                node = parent
            else:
                break

        return True

    def __len__(self) -> int:
        return self._count


class LinearCIDRRouter:
    """Baseline linear scan router used for comparative benchmarking."""

    def __init__(self) -> None:
        self.routes: list[tuple[ipaddress.IPv4Network, RouteEntry]] = []

    def insert(self, cidr: str, gateway: str, metric: int = 100, tag: str = "") -> None:
        net = ipaddress.IPv4Network(cidr, strict=False)
        self.routes.append((net, RouteEntry(cidr=cidr, gateway=gateway, metric=metric, tag=tag)))
        # Keep sorted by prefixlen descending
        self.routes.sort(key=lambda r: r[0].prefixlen, reverse=True)

    def lookup(self, ip_str: str) -> RouteEntry | None:
        ip = ipaddress.IPv4Address(ip_str)
        for net, entry in self.routes:
            if ip in net:
                return entry
        return None


def run_routing_benchmark(
    trie: IPv4RadixTrieRouter,
    linear: LinearCIDRRouter,
    test_ips: list[str],
    iterations: int = 5000,
) -> dict[str, Any]:
    """Execute high-precision comparative benchmark between Trie and Linear routing engines."""
    if not test_ips:
        return {"error": "no test IPs provided"}

    n_ips = len(test_ips)

    # Benchmark Radix Trie
    t0 = time.perf_counter()
    for i in range(iterations):
        ip = test_ips[i % n_ips]
        _ = trie.lookup(ip)
    trie_duration = time.perf_counter() - t0
    trie_lookups_per_sec = iterations / trie_duration if trie_duration > 0 else 0

    # Benchmark Linear Router
    t0 = time.perf_counter()
    for i in range(iterations):
        ip = test_ips[i % n_ips]
        _ = linear.lookup(ip)
    linear_duration = time.perf_counter() - t0
    linear_lookups_per_sec = iterations / linear_duration if linear_duration > 0 else 0

    speedup = linear_duration / trie_duration if trie_duration > 0 else 1.0

    return {
        "iterations": iterations,
        "route_table_size": len(trie),
        "trie_duration_ms": round(trie_duration * 1000, 3),
        "trie_lookups_per_sec": round(trie_lookups_per_sec, 1),
        "linear_duration_ms": round(linear_duration * 1000, 3),
        "linear_lookups_per_sec": round(linear_lookups_per_sec, 1),
        "speedup_factor": round(speedup, 2),
    }
