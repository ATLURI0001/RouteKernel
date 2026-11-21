"""Weighted Round-Robin & Health Canary Load Balancer for Ingress Gateways.

Implements Nginx-style smooth weighted round-robin selection and active health
probing for upstream application servers.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional


class UpstreamError(Exception):
    """Base exception for upstream load balancing errors."""


class AllUpstreamsUnhealthyError(UpstreamError):
    """Raised when no healthy upstream endpoints are available."""


class UpstreamNode:
    """Represents a target upstream server node."""

    def __init__(self, host: str, port: int, weight: int = 1):
        if not host or not isinstance(host, str):
            raise ValueError("host must be a non-empty string")
        if not (1 <= port <= 65535):
            raise ValueError(f"port out of range [1, 65535]: {port}")
        if weight <= 0:
            raise ValueError("weight must be a positive integer")

        self.host = host.strip()
        self.port = port
        self.weight = int(weight)
        self.effective_weight = int(weight)
        self.current_weight = 0

        self.is_healthy = True
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.last_failure_time = 0.0

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


class SmoothWeightedRoundRobin:
    """Nginx-style smooth weighted round-robin upstream distributor."""

    def __init__(self, fail_threshold: int = 3, pass_threshold: int = 2, cooldown_sec: float = 10.0):
        self.fail_threshold = fail_threshold
        self.pass_threshold = pass_threshold
        self.cooldown_sec = cooldown_sec
        self.nodes: Dict[str, UpstreamNode] = {}

    def add_node(self, host: str, port: int, weight: int = 1) -> UpstreamNode:
        """Registers a new upstream node."""
        node = UpstreamNode(host, port, weight)
        self.nodes[node.address] = node
        return node

    def remove_node(self, address: str) -> bool:
        """Removes a node by address."""
        return self.nodes.pop(address, None) is not None

    def select(self, now: Optional[float] = None) -> UpstreamNode:
        """Selects the next upstream node using smooth weighted round-robin.

        Algorithm:
        1. For each active healthy node: current_weight += effective_weight.
        2. Pick node with largest current_weight.
        3. For winner: current_weight -= total_effective_weight.
        """
        current_time = now if now is not None else time.time()
        self._refresh_health(current_time)

        healthy_nodes = [n for n in self.nodes.values() if n.is_healthy and n.effective_weight > 0]
        if not healthy_nodes:
            raise AllUpstreamsUnhealthyError("No healthy upstream nodes available")

        total_effective = sum(n.effective_weight for n in healthy_nodes)
        best_node: Optional[UpstreamNode] = None

        for node in healthy_nodes:
            node.current_weight += node.effective_weight
            if best_node is None or node.current_weight > best_node.current_weight:
                best_node = node

        if best_node is None:
            raise AllUpstreamsUnhealthyError("Selection failed unexpectedly")

        best_node.current_weight -= total_effective
        return best_node

    def record_success(self, address: str) -> None:
        """Marks successful request execution on a node."""
        node = self.nodes.get(address)
        if not node:
            return

        node.consecutive_failures = 0
        node.consecutive_successes += 1

        if not node.is_healthy and node.consecutive_successes >= self.pass_threshold:
            node.is_healthy = True
            node.effective_weight = node.weight
            node.current_weight = 0

    def record_failure(self, address: str, now: Optional[float] = None) -> None:
        """Marks request failure / timeout on a node."""
        node = self.nodes.get(address)
        if not node:
            return

        current_time = now if now is not None else time.time()
        node.consecutive_successes = 0
        node.consecutive_failures += 1
        node.last_failure_time = current_time

        if node.consecutive_failures >= self.fail_threshold:
            node.is_healthy = False
            node.effective_weight = 0

    def _refresh_health(self, current_time: float) -> None:
        """Permits canary probes on unhealthy nodes whose cooldown has expired."""
        for node in self.nodes.values():
            if not node.is_healthy:
                if current_time - node.last_failure_time >= self.cooldown_sec:
                    # Allocate 1 canary unit of effective weight for trial
                    node.effective_weight = 1
