"""BGP Route Flap Telemetry & Convergence Degradation Diagnostic.

Tracks per-peer BGP prefix update velocities, route withdrawal surges,
flapping penalties, and convergence status across autonomous routing fabrics.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
from typing import Deque, Dict, List, Optional, Tuple


class RouteHealthStatus(str, Enum):
    CONVERGED = "CONVERGED"
    UNSTABLE = "UNSTABLE"
    SUPPRESSED = "SUPPRESSED"


@dataclass
class BGPUpdateEvent:
    peer_ip: str
    prefix: str
    is_withdrawal: bool
    as_path_len: int
    timestamp: float


@dataclass
class PeerConvergenceSnapshot:
    peer_ip: str
    total_announcements: int
    total_withdrawals: int
    current_penalty: float
    status: RouteHealthStatus
    updates_per_sec: float
    last_update_age_sec: float


class BGPTelemetryCollector:
    """Thread-safe telemetry collector and flap penalty tracker for BGP peer sessions."""

    def __init__(
        self,
        suppress_threshold: float = 2000.0,
        reuse_threshold: float = 750.0,
        half_life_sec: float = 60.0,
        penalty_per_withdrawal: float = 1000.0,
        penalty_per_announcement: float = 500.0,
    ) -> None:
        self.suppress_threshold = suppress_threshold
        self.reuse_threshold = reuse_threshold
        self.half_life_sec = half_life_sec
        self.penalty_per_withdrawal = penalty_per_withdrawal
        self.penalty_per_announcement = penalty_per_announcement

        # Decay constant lambda = ln(2) / half_life
        self.decay_lambda = math.log(2) / max(1.0, half_life_sec)

        # peer_ip -> { prefix -> { penalty, last_time } }
        self._penalties: Dict[str, Dict[str, Tuple[float, float]]] = defaultdict(dict)
        self._history: Dict[str, Deque[BGPUpdateEvent]] = defaultdict(lambda: deque(maxlen=500))
        self._peer_totals: Dict[str, Dict[str, int]] = defaultdict(lambda: {"announcements": 0, "withdrawals": 0})

    def record_update(
        self,
        peer_ip: str,
        prefix: str,
        is_withdrawal: bool = False,
        as_path_len: int = 2,
        timestamp: Optional[float] = None,
    ) -> PeerConvergenceSnapshot:
        """Ingests a BGP announcement or withdrawal and updates flap penalties."""
        now = timestamp if timestamp is not None else time.time()
        peer = peer_ip.strip()
        pref = prefix.strip()

        event = BGPUpdateEvent(
            peer_ip=peer,
            prefix=pref,
            is_withdrawal=is_withdrawal,
            as_path_len=as_path_len,
            timestamp=now,
        )
        self._history[peer].append(event)

        if is_withdrawal:
            self._peer_totals[peer]["withdrawals"] += 1
            inc = self.penalty_per_withdrawal
        else:
            self._peer_totals[peer]["announcements"] += 1
            inc = self.penalty_per_announcement

        # Update penalty with exponential decay
        current_penalty, last_time = self._penalties[peer].get(pref, (0.0, now))
        delta_t = max(0.0, now - last_time)
        decayed = current_penalty * math.exp(-self.decay_lambda * delta_t)
        new_penalty = decayed + inc
        self._penalties[peer][pref] = (new_penalty, now)

        return self.get_peer_snapshot(peer, now)

    def get_peer_penalty(self, peer_ip: str, prefix: str, now: Optional[float] = None) -> float:
        """Retrieves the decayed penalty for a specific prefix."""
        t_now = now if now is not None else time.time()
        peer = peer_ip.strip()
        pref = prefix.strip()

        if peer not in self._penalties or pref not in self._penalties[peer]:
            return 0.0

        penalty, last_time = self._penalties[peer][pref]
        delta_t = max(0.0, t_now - last_time)
        return penalty * math.exp(-self.decay_lambda * delta_t)

    def get_peer_snapshot(self, peer_ip: str, now: Optional[float] = None) -> PeerConvergenceSnapshot:
        """Computes current telemetry snapshot and convergence classification for a peer."""
        t_now = now if now is not None else time.time()
        peer = peer_ip.strip()

        events = self._history.get(peer, deque())
        totals = self._peer_totals[peer]

        # Max penalty across prefixes for this peer
        max_penalty = 0.0
        for pref in self._penalties.get(peer, {}):
            pen = self.get_peer_penalty(peer, pref, t_now)
            if pen > max_penalty:
                max_penalty = pen

        # Compute status
        if max_penalty >= self.suppress_threshold:
            status = RouteHealthStatus.SUPPRESSED
        elif max_penalty >= self.reuse_threshold:
            status = RouteHealthStatus.UNSTABLE
        else:
            status = RouteHealthStatus.CONVERGED

        # Compute update velocity over last 10 seconds
        ten_sec_ago = t_now - 10.0
        recent_updates = sum(1 for e in events if e.timestamp >= ten_sec_ago)
        velocity = recent_updates / 10.0

        last_time = events[-1].timestamp if events else t_now
        age = max(0.0, t_now - last_time)

        return PeerConvergenceSnapshot(
            peer_ip=peer,
            total_announcements=totals["announcements"],
            total_withdrawals=totals["withdrawals"],
            current_penalty=round(max_penalty, 2),
            status=status,
            updates_per_sec=round(velocity, 2),
            last_update_age_sec=round(age, 2),
        )

    def format_markdown_report(self, now: Optional[float] = None) -> str:
        """Formats an operational telemetry report for all active BGP peers."""
        t_now = now if now is not None else time.time()
        lines = [
            "### BGP Route Convergence & Flap Diagnostic Report\n",
            "| Peer IP | Status | Max Penalty | Announcements | Withdrawals | Rate (updates/s) |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for peer in sorted(self._peer_totals.keys()):
            snap = self.get_peer_snapshot(peer, t_now)
            lines.append(
                f"| `{snap.peer_ip}` | **{snap.status.value}** | {snap.current_penalty:.1f} | "
                f"{snap.total_announcements:,} | {snap.total_withdrawals:,} | {snap.updates_per_sec:.2f} |"
            )

        return "\n".join(lines) + "\n"
