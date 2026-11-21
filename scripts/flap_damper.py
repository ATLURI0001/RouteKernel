"""RFC 2439-inspired Upstream Route Flap Damping and Oscillation Damper for RouteKernel."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional


class UpstreamState(str, Enum):
    HEALTHY = "HEALTHY"
    FLAPPING = "FLAPPING"
    SUPPRESSED = "SUPPRESSED"


@dataclass(frozen=True)
class FlapDampingConfig:
    """Configuration governing penalty accumulation, decay half-life, and suppression thresholds."""

    penalty_per_flap: float = 1000.0
    half_life_seconds: float = 15.0
    suppress_threshold: float = 2000.0
    reuse_threshold: float = 750.0
    max_suppress_seconds: float = 60.0

    def __post_init__(self) -> None:
        if self.penalty_per_flap <= 0:
            raise ValueError("penalty_per_flap must be > 0")
        if self.half_life_seconds <= 0:
            raise ValueError("half_life_seconds must be > 0")
        if self.suppress_threshold <= self.reuse_threshold:
            raise ValueError("suppress_threshold must be strictly greater than reuse_threshold")
        if self.reuse_threshold < 0:
            raise ValueError("reuse_threshold must be >= 0")
        if self.max_suppress_seconds <= 0:
            raise ValueError("max_suppress_seconds must be > 0")


class UpstreamTrackRecord:
    def __init__(self, upstream_id: str, initial_timestamp: float) -> None:
        self.upstream_id = upstream_id
        self.penalty = 0.0
        self.last_update = initial_timestamp
        self.last_health = True
        self.state = UpstreamState.HEALTHY
        self.suppressed_at: Optional[float] = None
        self.total_flaps = 0

    def decay_to(self, current_time: float, half_life: float) -> None:
        delta = max(0.0, current_time - self.last_update)
        if delta > 0 and self.penalty > 0:
            decay_factor = math.pow(2.0, -delta / half_life)
            self.penalty *= decay_factor
            if self.penalty < 1e-4:
                self.penalty = 0.0
        self.last_update = current_time


class RouteFlapDamper:
    """Manages routing penalties for flapping upstreams to guard load balancer topology."""

    def __init__(self, config: Optional[FlapDampingConfig] = None) -> None:
        self.config = config or FlapDampingConfig()
        self._records: Dict[str, UpstreamTrackRecord] = {}

    def _get_or_create(self, upstream_id: str, now: float) -> UpstreamTrackRecord:
        if upstream_id not in self._records:
            self._records[upstream_id] = UpstreamTrackRecord(upstream_id, now)
        return self._records[upstream_id]

    def record_state_change(
        self, upstream_id: str, is_healthy: bool, timestamp: Optional[float] = None
    ) -> UpstreamState:
        """Register a health status transition for an upstream host. Flaps increment penalty."""
        now = time.time() if timestamp is None else timestamp
        rec = self._get_or_create(upstream_id, now)

        # Decay existing penalty up to this point
        rec.decay_to(now, self.config.half_life_seconds)

        # Detect oscillation (health transition from True -> False or False -> True)
        if rec.last_health != is_healthy:
            rec.penalty += self.config.penalty_per_flap
            rec.total_flaps += 1
            rec.last_health = is_healthy

        # Evaluate suppression criteria
        if rec.state == UpstreamState.SUPPRESSED:
            # Check maximum suppression timeout
            if rec.suppressed_at is not None and (now - rec.suppressed_at) >= self.config.max_suppress_seconds:
                rec.state = UpstreamState.FLAPPING if rec.penalty > self.config.reuse_threshold else UpstreamState.HEALTHY
                rec.suppressed_at = None
            elif rec.penalty <= self.config.reuse_threshold:
                rec.state = UpstreamState.HEALTHY if is_healthy else UpstreamState.FLAPPING
                rec.suppressed_at = None
        else:
            if rec.penalty >= self.config.suppress_threshold:
                rec.state = UpstreamState.SUPPRESSED
                rec.suppressed_at = now
            elif rec.penalty > self.config.reuse_threshold:
                rec.state = UpstreamState.FLAPPING
            else:
                rec.state = UpstreamState.HEALTHY

        return rec.state

    def is_routable(self, upstream_id: str, timestamp: Optional[float] = None) -> bool:
        """Check if an upstream target is permitted to receive ingress traffic."""
        if upstream_id not in self._records:
            return True

        now = time.time() if timestamp is None else timestamp
        rec = self._records[upstream_id]
        rec.decay_to(now, self.config.half_life_seconds)

        if rec.state == UpstreamState.SUPPRESSED:
            # Check if auto-reuse criteria or max duration has expired
            if rec.suppressed_at is not None and (now - rec.suppressed_at) >= self.config.max_suppress_seconds:
                rec.state = UpstreamState.FLAPPING if rec.penalty > self.config.reuse_threshold else UpstreamState.HEALTHY
                rec.suppressed_at = None
                return rec.last_health
            if rec.penalty <= self.config.reuse_threshold:
                rec.state = UpstreamState.HEALTHY if rec.last_health else UpstreamState.FLAPPING
                rec.suppressed_at = None
                return rec.last_health
            return False

        return rec.last_health

    def get_upstream_status(self, upstream_id: str, timestamp: Optional[float] = None) -> dict:
        """Retrieve diagnostic snapshot for a specific upstream."""
        now = time.time() if timestamp is None else timestamp
        if upstream_id not in self._records:
            return {
                "upstream_id": upstream_id,
                "state": UpstreamState.HEALTHY.value,
                "penalty": 0.0,
                "total_flaps": 0,
                "routable": True,
            }

        rec = self._records[upstream_id]
        rec.decay_to(now, self.config.half_life_seconds)
        routable = self.is_routable(upstream_id, now)

        return {
            "upstream_id": upstream_id,
            "state": rec.state.value,
            "penalty": round(rec.penalty, 2),
            "total_flaps": rec.total_flaps,
            "routable": routable,
            "suppressed": rec.state == UpstreamState.SUPPRESSED,
        }

    def reset(self, upstream_id: Optional[str] = None) -> None:
        """Reset penalties and suppressions for one or all upstreams."""
        if upstream_id is not None:
            self._records.pop(upstream_id, None)
        else:
            self._records.clear()
