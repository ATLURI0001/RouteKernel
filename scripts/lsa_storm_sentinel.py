"""
RouteKernel - OSPF Link-State Advertisement (LSA) Flooding Storm Failsafe Sentinel.

Defends against high-frequency OSPF LSA flooding loops, link-flap storm cascades,
MinLSArrival violations, sequence number rollover attacks, and SPF Dijkstra CPU starvation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class LSAType(int, Enum):
    ROUTER = 1
    NETWORK = 2
    SUMMARY_NET = 3
    SUMMARY_ASBR = 4
    AS_EXTERNAL = 5


class LSAViolationCode(str, Enum):
    MIN_LS_ARRIVAL_BREACH = "ERR_MIN_LS_ARRIVAL_BREACH"
    STORM_RATE_EXCEEDED = "ERR_LSA_STORM_RATE_EXCEEDED"
    STALE_SEQUENCE_NUMBER = "ERR_STALE_SEQUENCE_NUMBER"
    QUARANTINED_ADVERTISER = "ERR_ADVERTISER_IN_QUARANTINE"
    MALFORMED_LSA = "ERR_MALFORMED_LSA_HEADER"


class LSAAction(str, Enum):
    ACCEPTED = "ACCEPTED"
    SUPPRESSED = "SUPPRESSED"
    QUARANTINED = "QUARANTINED"


@dataclass
class LSAHeader:
    """OSPF Link-State Advertisement Header Representation (RFC 2328 §12)."""
    lsa_type: LSAType
    link_state_id: str
    advertising_router: str
    sequence_number: int
    checksum: int
    age_seconds: int = 0
    area_id: str = "0.0.0.0"


@dataclass
class AdvertiserState:
    """Maintains arrival history and rate-limiting metrics for an advertising router."""
    router_id: str
    last_lsa_timestamp: float = 0.0
    arrival_timestamps: List[float] = field(default_factory=list)
    last_sequence_numbers: Dict[Tuple[int, str], int] = field(default_factory=dict)
    quarantine_until: float = 0.0
    total_received: int = 0
    total_suppressed: int = 0


@dataclass
class LSAEvaluationResult:
    """Outcome of an LSA inspection."""
    action: LSAAction
    advertising_router: str
    lsa_type: LSAType
    link_state_id: str
    violation_code: Optional[LSAViolationCode] = None
    reason: str = "Nominal LSA admission"
    timestamp: float = field(default_factory=time.time)


@dataclass
class IncidentReportEntry:
    """Incident log entry for LSA storm postmortem analysis."""
    incident_id: str
    router_id: str
    peak_rate_per_sec: float
    trigger_reason: str
    quarantine_duration_sec: float
    timestamp: float = field(default_factory=time.time)


class LSAStormSentinel:
    """
    OSPF LSA Flood Sentinel.
    Protects router control planes from link-flap storms, duplicate floods, and SPF recalculation loops.
    """

    def __init__(
        self,
        min_ls_arrival_sec: float = 1.0,
        max_lsas_per_window: int = 20,
        rate_window_sec: float = 5.0,
        quarantine_duration_sec: float = 30.0,
    ) -> None:
        self.min_ls_arrival_sec = max(0.01, float(min_ls_arrival_sec))
        self.max_lsas_per_window = max(1, int(max_lsas_per_window))
        self.rate_window_sec = max(0.1, float(rate_window_sec))
        self.quarantine_duration_sec = max(1.0, float(quarantine_duration_sec))

        self.advertisers: Dict[str, AdvertiserState] = {}
        self.incidents: List[IncidentReportEntry] = []
        self.total_processed = 0
        self.total_accepted = 0
        self.total_suppressed = 0

    def inspect_lsa(
        self,
        lsa: LSAHeader,
        current_time: Optional[float] = None,
    ) -> LSAEvaluationResult:
        """Inspects an incoming LSA and enforces rate boundaries and storm damping."""
        now = current_time if current_time is not None else time.time()
        self.total_processed += 1

        if not lsa or not lsa.advertising_router or not lsa.link_state_id:
            self.total_suppressed += 1
            return LSAEvaluationResult(
                action=LSAAction.SUPPRESSED,
                advertising_router=getattr(lsa, "advertising_router", "UNKNOWN"),
                lsa_type=getattr(lsa, "lsa_type", LSAType.ROUTER),
                link_state_id=getattr(lsa, "link_state_id", "UNKNOWN"),
                violation_code=LSAViolationCode.MALFORMED_LSA,
                reason="Malformed LSA: missing advertising router or link-state ID",
                timestamp=now,
            )

        router_id = lsa.advertising_router
        if router_id not in self.advertisers:
            self.advertisers[router_id] = AdvertiserState(router_id=router_id)

        state = self.advertisers[router_id]
        state.total_received += 1

        # 1. Check if router is in quarantine hold-down
        if now < state.quarantine_until:
            state.total_suppressed += 1
            self.total_suppressed += 1
            remaining = round(state.quarantine_until - now, 1)
            return LSAEvaluationResult(
                action=LSAAction.QUARANTINED,
                advertising_router=router_id,
                lsa_type=lsa.lsa_type,
                link_state_id=lsa.link_state_id,
                violation_code=LSAViolationCode.QUARANTINED_ADVERTISER,
                reason=f"Advertiser {router_id} is quarantined in storm hold-down ({remaining}s remaining)",
                timestamp=now,
            )

        # 2. Check MinLSArrival boundary (RFC 2328 §13)
        lsa_key = (int(lsa.lsa_type), lsa.link_state_id)
        time_since_last = now - state.last_lsa_timestamp

        if state.last_lsa_timestamp > 0.0 and time_since_last < self.min_ls_arrival_sec:
            state.total_suppressed += 1
            self.total_suppressed += 1
            return LSAEvaluationResult(
                action=LSAAction.SUPPRESSED,
                advertising_router=router_id,
                lsa_type=lsa.lsa_type,
                link_state_id=lsa.link_state_id,
                violation_code=LSAViolationCode.MIN_LS_ARRIVAL_BREACH,
                reason=f"LSA arrived too rapidly ({time_since_last:.3f}s < {self.min_ls_arrival_sec}s MinLSArrival)",
                timestamp=now,
            )

        # 3. Check Sequence Number Stale / Duplicate
        last_seq = state.last_sequence_numbers.get(lsa_key)
        if last_seq is not None and lsa.sequence_number <= last_seq:
            state.total_suppressed += 1
            self.total_suppressed += 1
            return LSAEvaluationResult(
                action=LSAAction.SUPPRESSED,
                advertising_router=router_id,
                lsa_type=lsa.lsa_type,
                link_state_id=lsa.link_state_id,
                violation_code=LSAViolationCode.STALE_SEQUENCE_NUMBER,
                reason=f"Stale sequence number 0x{lsa.sequence_number:08X} <= 0x{last_seq:08X}",
                timestamp=now,
            )

        # 4. Check Sliding-Window Arrival Storm Rate
        # Prune timestamps older than rate_window_sec
        window_cutoff = now - self.rate_window_sec
        state.arrival_timestamps = [ts for ts in state.arrival_timestamps if ts >= window_cutoff]
        state.arrival_timestamps.append(now)

        if len(state.arrival_timestamps) > self.max_lsas_per_window:
            # Storm threshold breached: quarantine router!
            state.quarantine_until = now + self.quarantine_duration_sec
            state.total_suppressed += 1
            self.total_suppressed += 1

            peak_rate = round(len(state.arrival_timestamps) / self.rate_window_sec, 2)
            incident_id = f"LSA-STORM-{router_id}-{int(now)}"
            self.incidents.append(IncidentReportEntry(
                incident_id=incident_id,
                router_id=router_id,
                peak_rate_per_sec=peak_rate,
                trigger_reason=f"Arrival count ({len(state.arrival_timestamps)}) exceeded window ceiling ({self.max_lsas_per_window})",
                quarantine_duration_sec=self.quarantine_duration_sec,
                timestamp=now,
            ))

            return LSAEvaluationResult(
                action=LSAAction.QUARANTINED,
                advertising_router=router_id,
                lsa_type=lsa.lsa_type,
                link_state_id=lsa.link_state_id,
                violation_code=LSAViolationCode.STORM_RATE_EXCEEDED,
                reason=f"LSA storm detected from {router_id} ({peak_rate} LSA/s); entering {self.quarantine_duration_sec}s quarantine",
                timestamp=now,
            )

        # 5. LSA Accepted: Update State
        state.last_lsa_timestamp = now
        state.last_sequence_numbers[lsa_key] = lsa.sequence_number
        self.total_accepted += 1

        return LSAEvaluationResult(
            action=LSAAction.ACCEPTED,
            advertising_router=router_id,
            lsa_type=lsa.lsa_type,
            link_state_id=lsa.link_state_id,
            reason="LSA accepted within nominal rate and sequence bounds",
            timestamp=now,
        )

    def release_quarantine(self, router_id: str) -> bool:
        """Manually releases a router from storm quarantine."""
        state = self.advertisers.get(router_id)
        if state and state.quarantine_until > 0.0:
            state.quarantine_until = 0.0
            return True
        return False

    def get_telemetry(self) -> Dict[str, Any]:
        """Returns operational telemetry metrics."""
        return {
            "total_processed": self.total_processed,
            "total_accepted": self.total_accepted,
            "total_suppressed": self.total_suppressed,
            "quarantined_advertisers_count": sum(
                1 for s in self.advertisers.values() if s.quarantine_until > time.time()
            ),
            "incidents_logged": len(self.incidents),
        }

    def generate_postmortem_report(self) -> str:
        """Generates a structured Markdown incident postmortem log."""
        if not self.incidents:
            return "# Incident Postmortem: No OSPF LSA Storms Detected\n\nAll Link-State Advertisements conformed to MinLSArrival and window limits."

        lines = [
            "# Incident Postmortem: OSPF LSA Flooding Storm Mitigation Report",
            "",
            f"- **Total LSAs Ingested:** `{self.total_processed}`",
            f"- **Accepted:** `{self.total_accepted}`",
            f"- **Suppressed / Storm-Damped:** `{self.total_suppressed}`",
            f"- **Storm Incidents Logged:** `{len(self.incidents)}`",
            "",
            "## Storm Incident Timeline",
            "| Incident ID | Offender Router ID | Peak Rate (LSA/s) | Quarantine Duration | Root Cause |",
            "|---|---|---|---|---|",
        ]

        for inc in self.incidents:
            lines.append(
                f"| `{inc.incident_id}` | `{inc.router_id}` | {inc.peak_rate_per_sec} LSA/s | "
                f"{inc.quarantine_duration_sec}s | {inc.trigger_reason} |"
            )

        return "\n".join(lines)
