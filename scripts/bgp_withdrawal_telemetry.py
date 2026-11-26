"""BGP Prefix Withdrawal Velocity & Convergence Latency Telemetry Rotary.

Provides sliding-window telemetry, withdrawal velocity tracking,
convergence latency histograms, and route withdrawal storm detection
for autonomous routing fabrics and border gateways.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Tuple


class WithdrawalAlertLevel(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    CRITICAL = "CRITICAL"
    STORM = "STORM"


@dataclass
class WithdrawalEvent:
    peer_ip: str
    asn: int
    prefix: str
    timestamp: float
    convergence_duration_ms: Optional[float] = None


@dataclass
class WithdrawalRateSnapshot:
    window_sec: float
    total_withdrawals: int
    velocity_per_sec: float
    affected_prefixes: int
    affected_peers: int
    affected_asns: int
    alert_level: WithdrawalAlertLevel


@dataclass
class ConvergenceLatencyStats:
    sample_count: int
    min_ms: float
    max_ms: float
    mean_ms: float
    p50_ms: float
    p90_ms: float
    p99_ms: float


@dataclass
class RotaryTelemetrySummary:
    total_events_recorded: int
    active_peers_count: int
    active_asns_count: int
    short_window_snapshot: WithdrawalRateSnapshot  # e.g. 5s
    medium_window_snapshot: WithdrawalRateSnapshot  # e.g. 30s
    long_window_snapshot: WithdrawalRateSnapshot  # e.g. 60s
    latency_stats: ConvergenceLatencyStats
    top_churn_asns: List[Tuple[int, int]]
    top_churn_peers: List[Tuple[str, int]]


class BGPWithdrawalTelemetryRotary:
    """Bounded ring buffer tracking BGP withdrawal velocity and convergence latency."""

    def __init__(
        self,
        buffer_capacity: int = 10000,
        elevated_threshold_per_sec: float = 10.0,
        critical_threshold_per_sec: float = 50.0,
        storm_threshold_per_sec: float = 200.0,
    ) -> None:
        self.buffer_capacity = max(100, buffer_capacity)
        self.elevated_threshold = elevated_threshold_per_sec
        self.critical_threshold = critical_threshold_per_sec
        self.storm_threshold = storm_threshold_per_sec

        self._ring: Deque[WithdrawalEvent] = deque(maxlen=self.buffer_capacity)
        self._latencies: Deque[float] = deque(maxlen=self.buffer_capacity)
        self._total_recorded: int = 0
        self._asn_counts: Dict[int, int] = defaultdict(int)
        self._peer_counts: Dict[str, int] = defaultdict(int)

    def record_withdrawal(
        self,
        peer_ip: str,
        asn: int,
        prefix: str,
        timestamp: Optional[float] = None,
        convergence_duration_ms: Optional[float] = None,
    ) -> WithdrawalEvent:
        """Ingests a withdrawal event with optional convergence measurement."""
        ts = timestamp if timestamp is not None else time.time()
        event = WithdrawalEvent(
            peer_ip=peer_ip.strip(),
            asn=asn,
            prefix=prefix.strip(),
            timestamp=ts,
            convergence_duration_ms=convergence_duration_ms,
        )

        self._ring.append(event)
        self._total_recorded += 1
        self._asn_counts[asn] += 1
        self._peer_counts[peer_ip.strip()] += 1

        if convergence_duration_ms is not None and convergence_duration_ms >= 0:
            self._latencies.append(convergence_duration_ms)

        return event

    def get_rate_snapshot(self, window_sec: float = 60.0, now: Optional[float] = None) -> WithdrawalRateSnapshot:
        """Computes rate snapshot across specified sliding window duration."""
        current_time = now if now is not None else time.time()
        start_threshold = current_time - window_sec

        prefixes = set()
        peers = set()
        asns = set()
        count = 0

        # Traverse backwards from latest events
        for event in reversed(self._ring):
            if event.timestamp < start_threshold:
                break
            count += 1
            prefixes.add(event.prefix)
            peers.add(event.peer_ip)
            asns.add(event.asn)

        effective_sec = max(0.001, window_sec)
        velocity = count / effective_sec

        if velocity >= self.storm_threshold:
            alert = WithdrawalAlertLevel.STORM
        elif velocity >= self.critical_threshold:
            alert = WithdrawalAlertLevel.CRITICAL
        elif velocity >= self.elevated_threshold:
            alert = WithdrawalAlertLevel.ELEVATED
        else:
            alert = WithdrawalAlertLevel.NORMAL

        return WithdrawalRateSnapshot(
            window_sec=window_sec,
            total_withdrawals=count,
            velocity_per_sec=round(velocity, 2),
            affected_prefixes=len(prefixes),
            affected_peers=len(peers),
            affected_asns=len(asns),
            alert_level=alert,
        )

    def compute_latency_stats(self) -> ConvergenceLatencyStats:
        """Computes percentile summary for measured convergence latencies."""
        if not self._latencies:
            return ConvergenceLatencyStats(
                sample_count=0,
                min_ms=0.0,
                max_ms=0.0,
                mean_ms=0.0,
                p50_ms=0.0,
                p90_ms=0.0,
                p99_ms=0.0,
            )

        sorted_latencies = sorted(self._latencies)
        n = len(sorted_latencies)

        def percentile(p: float) -> float:
            k = (n - 1) * (p / 100.0)
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                return sorted_latencies[int(k)]
            d0 = sorted_latencies[int(f)] * (c - k)
            d1 = sorted_latencies[int(c)] * (k - f)
            return d0 + d1

        min_val = sorted_latencies[0]
        max_val = sorted_latencies[-1]
        mean_val = sum(sorted_latencies) / n

        return ConvergenceLatencyStats(
            sample_count=n,
            min_ms=round(min_val, 2),
            max_ms=round(max_val, 2),
            mean_ms=round(mean_val, 2),
            p50_ms=round(percentile(50.0), 2),
            p90_ms=round(percentile(90.0), 2),
            p99_ms=round(percentile(99.0), 2),
        )

    def get_summary(
        self,
        now: Optional[float] = None,
        top_k: int = 5,
    ) -> RotaryTelemetrySummary:
        """Produces overall telemetry rotary summary."""
        snap_short = self.get_rate_snapshot(window_sec=5.0, now=now)
        snap_med = self.get_rate_snapshot(window_sec=30.0, now=now)
        snap_long = self.get_rate_snapshot(window_sec=60.0, now=now)
        latency = self.compute_latency_stats()

        top_asns = sorted(self._asn_counts.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
        top_peers = sorted(self._peer_counts.items(), key=lambda kv: kv[1], reverse=True)[:top_k]

        return RotaryTelemetrySummary(
            total_events_recorded=self._total_recorded,
            active_peers_count=len(self._peer_counts),
            active_asns_count=len(self._asn_counts),
            short_window_snapshot=snap_short,
            medium_window_snapshot=snap_med,
            long_window_snapshot=snap_long,
            latency_stats=latency,
            top_churn_asns=top_asns,
            top_churn_peers=top_peers,
        )

    def format_markdown_report(self, now: Optional[float] = None) -> str:
        """Renders an operator-friendly markdown telemetry diagnostics view."""
        summary = self.get_summary(now=now)
        lines = [
            "# BGP Prefix Withdrawal Velocity & Convergence Rotary",
            "",
            "| Metric | Value |",
            "| :--- | :--- |",
            f"| **Total Recorded Events** | `{summary.total_events_recorded}` |",
            f"| **Unique Peers Tracked** | `{summary.active_peers_count}` |",
            f"| **Unique ASNs Tracked** | `{summary.active_asns_count}` |",
            f"| **Short Window (5s) Velocity** | `{summary.short_window_snapshot.velocity_per_sec} w/s` ({summary.short_window_snapshot.alert_level.value}) |",
            f"| **Medium Window (30s) Velocity** | `{summary.medium_window_snapshot.velocity_per_sec} w/s` ({summary.medium_window_snapshot.alert_level.value}) |",
            f"| **Long Window (60s) Velocity** | `{summary.long_window_snapshot.velocity_per_sec} w/s` ({summary.long_window_snapshot.alert_level.value}) |",
            "",
            "### Convergence Latency Distribution",
            "| Sample Count | Min | P50 (Median) | P90 | P99 | Max | Mean |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            f"| {summary.latency_stats.sample_count} | {summary.latency_stats.min_ms} ms | {summary.latency_stats.p50_ms} ms | {summary.latency_stats.p90_ms} ms | {summary.latency_stats.p99_ms} ms | {summary.latency_stats.max_ms} ms | {summary.latency_stats.mean_ms} ms |",
            "",
            "### Top Churn ASNs",
        ]

        if summary.top_churn_asns:
            for asn, count in summary.top_churn_asns:
                lines.append(f"- **AS{asn}**: {count} withdrawals")
        else:
            lines.append("- *No churn events observed.*")

        lines.append("")
        lines.append("### Top Churn Peers")
        if summary.top_churn_peers:
            for peer, count in summary.top_churn_peers:
                lines.append(f"- `{peer}`: {count} withdrawals")
        else:
            lines.append("- *No churn peers observed.*")

        return "\n".join(lines)
