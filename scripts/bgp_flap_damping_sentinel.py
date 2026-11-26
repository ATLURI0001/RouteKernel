"""INC-2026-ROUTE-8831: BGP Route Flap Damping & RIB Churn Sentinel.

Implements RFC 2439 route flap damping algorithms to protect routing information
bases (RIB) from pathological route withdrawals and announcements.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class RouteState(str, Enum):
    UNSUPPRESSED = "UNSUPPRESSED"
    SUPPRESSED = "SUPPRESSED"


@dataclass
class PrefixFlapState:
    prefix: str
    peer_ip: str
    penalty: float = 0.0
    last_update_epoch: float = 0.0
    flap_count: int = 0
    state: RouteState = RouteState.UNSUPPRESSED
    suppression_start_epoch: float = 0.0


@dataclass
class FlapSentinelReport:
    prefix: str
    state: RouteState
    current_penalty: float
    total_flaps: int
    suppression_active: bool
    incident_flagged: bool


class BgpFlapDampingSentinel:
    """Monitors and dampens oscillating BGP prefixes under RFC 2439 invariants."""

    def __init__(
        self,
        suppress_threshold: float = 2500.0,
        reuse_threshold: float = 750.0,
        penalty_per_flap: float = 1000.0,
        half_life_seconds: float = 900.0,  # 15 minutes default
        max_suppress_seconds: float = 3600.0,  # 1 hour
    ) -> None:
        self.suppress_threshold = suppress_threshold
        self.reuse_threshold = reuse_threshold
        self.penalty_per_flap = penalty_per_flap
        self.half_life_seconds = half_life_seconds
        self.max_suppress_seconds = max_suppress_seconds

        self.prefixes: Dict[str, PrefixFlapState] = {}
        self.incidents: List[str] = []

    def _decay_penalty(self, state: PrefixFlapState, now: float) -> None:
        if state.last_update_epoch <= 0:
            return
        elapsed = max(0.0, now - state.last_update_epoch)
        if elapsed > 0 and self.half_life_seconds > 0:
            decay_factor = math.pow(0.5, elapsed / self.half_life_seconds)
            state.penalty = state.penalty * decay_factor

    def record_flap(self, prefix: str, peer_ip: str, now: float) -> FlapSentinelReport:
        key = f"{peer_ip}:{prefix}"
        if key not in self.prefixes:
            self.prefixes[key] = PrefixFlapState(prefix=prefix, peer_ip=peer_ip, last_update_epoch=now)

        state = self.prefixes[key]
        self._decay_penalty(state, now)

        # Apply flap penalty
        state.penalty += self.penalty_per_flap
        state.flap_count += 1
        state.last_update_epoch = now

        incident_flagged = False
        if state.state == RouteState.UNSUPPRESSED and state.penalty >= self.suppress_threshold:
            state.state = RouteState.SUPPRESSED
            state.suppression_start_epoch = now
            incident_flagged = True
            self.incidents.append(f"INC-2026-ROUTE-8831: Prefix {prefix} suppressed (penalty: {state.penalty:.1f})")

        return FlapSentinelReport(
            prefix=prefix,
            state=state.state,
            current_penalty=round(state.penalty, 2),
            total_flaps=state.flap_count,
            suppression_active=(state.state == RouteState.SUPPRESSED),
            incident_flagged=incident_flagged,
        )

    def evaluate_route(self, prefix: str, peer_ip: str, now: float) -> RouteState:
        key = f"{peer_ip}:{prefix}"
        if key not in self.prefixes:
            return RouteState.UNSUPPRESSED

        state = self.prefixes[key]
        self._decay_penalty(state, now)
        state.last_update_epoch = now

        if state.state == RouteState.SUPPRESSED:
            # Check maximum suppression window timeout
            if (now - state.suppression_start_epoch) >= self.max_suppress_seconds:
                state.state = RouteState.UNSUPPRESSED
                state.penalty = min(state.penalty, self.reuse_threshold)
            elif state.penalty <= self.reuse_threshold:
                state.state = RouteState.UNSUPPRESSED

        return state.state
