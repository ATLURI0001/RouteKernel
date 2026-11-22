"""Dynamic Anycast PoP Health Prober and Geo-DNS Failover Rotary Engine.

Provides continuous edge latency telemetry, flap-damped health state transitions,
and automatic regional failover routing for distributed network topologies.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ProbeResult:
    """Outcome of an individual synthetic probe against an Anycast PoP."""

    pop_id: str
    timestamp: float
    latency_ms: float
    success: bool
    status_code: int = 200
    error_message: Optional[str] = None


@dataclass
class PoPNode:
    """Represents an edge Point-of-Presence (PoP) in the Anycast mesh."""

    pop_id: str
    region: str
    ip_address: str
    weight: int = 100
    healthy: bool = True
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    total_probes: int = 0
    total_failures: int = 0
    latency_history: List[float] = field(default_factory=list)
    last_probe_time: float = 0.0


class AnycastFailoverRotary:
    """Manages PoP lifecycle, health damping, and regional failover selection."""

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_threshold: int = 2,
        max_latency_ms: float = 350.0,
        history_window: int = 50,
    ) -> None:
        self.failure_threshold = max(1, int(failure_threshold))
        self.recovery_threshold = max(1, int(recovery_threshold))
        self.max_latency_ms = max(50.0, float(max_latency_ms))
        self.history_window = max(5, int(history_window))

        self.pops: Dict[str, PoPNode] = {}
        self.regional_distance_matrix: Dict[str, Dict[str, float]] = {
            "us-east": {"us-east": 0.0, "us-west": 45.0, "eu-west": 70.0, "ap-south": 180.0},
            "us-west": {"us-west": 0.0, "us-east": 45.0, "eu-west": 110.0, "ap-south": 150.0},
            "eu-west": {"eu-west": 0.0, "us-east": 70.0, "us-west": 110.0, "ap-south": 120.0},
            "ap-south": {"ap-south": 0.0, "eu-west": 120.0, "us-west": 150.0, "us-east": 180.0},
        }

    def register_pop(
        self, pop_id: str, region: str, ip_address: str, weight: int = 100
    ) -> PoPNode:
        """Registers a new Point-of-Presence node in the rotary."""
        clean_id = pop_id.strip().lower()
        if not clean_id:
            raise ValueError("PoP ID must not be empty")
        if not region.strip():
            raise ValueError("Region must not be empty")
        if weight <= 0:
            raise ValueError("Weight must be strictly positive")

        node = PoPNode(
            pop_id=clean_id,
            region=region.strip().lower(),
            ip_address=ip_address.strip(),
            weight=weight,
            healthy=True,
        )
        self.pops[clean_id] = node
        return node

    def record_probe(self, result: ProbeResult) -> bool:
        """Records a probe outcome and computes flap-damped state transitions.

        Returns:
            The updated health status of the PoP.
        """
        node = self.pops.get(result.pop_id.lower())
        if not node:
            raise KeyError(f"Unregistered PoP: '{result.pop_id}'")

        node.total_probes += 1
        node.last_probe_time = result.timestamp

        is_effective_success = (
            result.success
            and result.status_code < 400
            and result.latency_ms <= self.max_latency_ms
        )

        if is_effective_success:
            node.consecutive_successes += 1
            node.consecutive_failures = 0
            node.latency_history.append(result.latency_ms)
            if len(node.latency_history) > self.history_window:
                node.latency_history.pop(0)

            # Recovery transition requires meeting the threshold
            if not node.healthy and node.consecutive_successes >= self.recovery_threshold:
                node.healthy = True
        else:
            node.total_failures += 1
            node.consecutive_failures += 1
            node.consecutive_successes = 0

            # Flap damping: failure transition requires meeting the threshold
            if node.healthy and node.consecutive_failures >= self.failure_threshold:
                node.healthy = False

        return node.healthy

    def select_optimal_pop(self, client_region: str) -> Optional[PoPNode]:
        """Selects the best healthy Anycast PoP for a client's region.

        Evaluates regional proximity, observed RTT, and capacity weight.
        """
        norm_region = client_region.strip().lower()
        healthy_pops = [p for p in self.pops.values() if p.healthy]
        if not healthy_pops:
            return None

        # 1. Prefer healthy PoP in exact matching client region
        same_region_pops = [p for p in healthy_pops if p.region == norm_region]
        if same_region_pops:
            return self._best_pop_in_subset(same_region_pops)

        # 2. Regional failover: rank remaining healthy PoPs by geographic distance + observed latency
        def _score(p: PoPNode) -> float:
            base_dist = self.regional_distance_matrix.get(norm_region, {}).get(p.region, 200.0)
            avg_rtt = sum(p.latency_history) / len(p.latency_history) if p.latency_history else 50.0
            # Lower score is better
            return (base_dist * 0.6) + (avg_rtt * 0.4) - (p.weight * 0.05)

        return min(healthy_pops, key=_score)

    def _best_pop_in_subset(self, candidates: List[PoPNode]) -> PoPNode:
        """Picks the highest weight / lowest latency PoP from candidate list."""
        def _rank(p: PoPNode) -> Tuple[float, int]:
            avg_rtt = sum(p.latency_history) / len(p.latency_history) if p.latency_history else 20.0
            return (avg_rtt, -p.weight)

        return min(candidates, key=_rank)

    def get_health_report(self) -> Dict[str, Any]:
        """Computes comprehensive health telemetry and loss statistics."""
        pop_reports: Dict[str, Any] = {}
        healthy_count = 0

        for pop_id, p in self.pops.items():
            if p.healthy:
                healthy_count += 1
            avg_lat = sum(p.latency_history) / len(p.latency_history) if p.latency_history else 0.0
            loss_pct = (p.total_failures / p.total_probes * 100.0) if p.total_probes > 0 else 0.0
            pop_reports[pop_id] = {
                "region": p.region,
                "healthy": p.healthy,
                "consecutive_failures": p.consecutive_failures,
                "consecutive_successes": p.consecutive_successes,
                "avg_latency_ms": round(avg_lat, 2),
                "packet_loss_pct": round(loss_pct, 2),
                "weight": p.weight,
            }

        total_nodes = len(self.pops)
        availability_pct = (healthy_count / total_nodes * 100.0) if total_nodes > 0 else 0.0

        return {
            "total_pops": total_nodes,
            "healthy_pops": healthy_count,
            "overall_availability_pct": round(availability_pct, 2),
            "pops": pop_reports,
        }

    def reset(self) -> None:
        """Clears all registered PoPs and state history."""
        self.pops.clear()
