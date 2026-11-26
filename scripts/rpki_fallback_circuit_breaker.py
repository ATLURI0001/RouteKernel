"""
RPKI ROA Validation Fallback Circuit Breaker for RouteKernel.

Provides three-state resilience (CLOSED, OPEN, HALF_OPEN) against RPKI RTR
validator failure storms, cache desynchronization, and ROA propagation outages.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


class CircuitState(str, enum.Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class RPKIValidationState(str, enum.Enum):
    VALID = "VALID"
    NOT_FOUND = "NOT_FOUND"
    INVALID = "INVALID"
    VALIDATOR_ERROR = "VALIDATOR_ERROR"


class FallbackPolicy(str, enum.Enum):
    DROP_INVALID = "DROP_INVALID"
    FALLBACK_SECONDARY_RTR = "FALLBACK_SECONDARY_RTR"
    FAILSAFE_CONSERVATIVE = "FAILSAFE_CONSERVATIVE"


@dataclass
class RPKIRouteAnnouncement:
    prefix: str
    origin_as: int
    peer_ip: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class RPKIFallbackResult:
    route: RPKIRouteAnnouncement
    validation_state: RPKIValidationState
    circuit_state: CircuitState
    policy_applied: FallbackPolicy
    routed: bool
    fallback_engaged: bool
    diagnostic: str


class RPKIFallbackCircuitBreaker:
    """Guards BGP routing policy against RPKI validator outages and failure spikes."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_sec: float = 30.0,
        half_open_success_threshold: int = 3,
        primary_validator: Optional[Callable[[RPKIRouteAnnouncement], RPKIValidationState]] = None,
        secondary_validator: Optional[Callable[[RPKIRouteAnnouncement], RPKIValidationState]] = None,
    ):
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if recovery_timeout_sec <= 0:
            raise ValueError("recovery_timeout_sec must be positive")
        if half_open_success_threshold < 1:
            raise ValueError("half_open_success_threshold must be at least 1")

        self.failure_threshold = failure_threshold
        self.recovery_timeout_sec = recovery_timeout_sec
        self.half_open_success_threshold = half_open_success_threshold

        self.primary_validator = primary_validator
        self.secondary_validator = secondary_validator

        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._last_state_change = time.time()
        self._last_failure_time = 0.0
        self._trip_count = 0
        self._total_evaluated = 0
        self._fallback_invocations = 0

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def trip_count(self) -> int:
        return self._trip_count

    def evaluate_route(
        self,
        route: RPKIRouteAnnouncement,
        now: Optional[float] = None,
    ) -> RPKIFallbackResult:
        """Evaluate an inbound BGP route against RPKI validation with circuit breaker guard."""
        current_time = time.time() if now is None else now
        self._total_evaluated += 1

        # Check for OPEN -> HALF_OPEN timeout transition
        if self._state == CircuitState.OPEN:
            if current_time - self._last_state_change >= self.recovery_timeout_sec:
                self._state = CircuitState.HALF_OPEN
                self._consecutive_successes = 0
                self._last_state_change = current_time

        # If CLOSED or HALF_OPEN, attempt primary validator
        if self._state in (CircuitState.CLOSED, CircuitState.HALF_OPEN):
            try:
                if self.primary_validator is None:
                    raise RuntimeError("No primary RPKI validator configured")
                validation = self.primary_validator(route)
            except Exception as exc:
                validation = RPKIValidationState.VALIDATOR_ERROR

            if validation == RPKIValidationState.VALIDATOR_ERROR:
                return self._handle_primary_failure(route, current_time, "Primary validator threw exception")
            elif validation == RPKIValidationState.INVALID:
                # Legitimate RPKI INVALID route from primary
                self._record_primary_success()
                return RPKIFallbackResult(
                    route=route,
                    validation_state=RPKIValidationState.INVALID,
                    circuit_state=self._state,
                    policy_applied=FallbackPolicy.DROP_INVALID,
                    routed=False,
                    fallback_engaged=False,
                    diagnostic="RPKI validation INVALID: origin AS unauthorized by ROA",
                )
            else:
                # VALID or NOT_FOUND
                self._record_primary_success()
                return RPKIFallbackResult(
                    route=route,
                    validation_state=validation,
                    circuit_state=self._state,
                    policy_applied=FallbackPolicy.DROP_INVALID,
                    routed=True,
                    fallback_engaged=False,
                    diagnostic=f"Route accepted with RPKI state {validation.value}",
                )

        # If OPEN: immediately engage fallback policy
        return self._execute_fallback(route, current_time, "Circuit OPEN: Primary validator bypass active")

    def _record_primary_success(self):
        """Record successful validation attempt from primary validator."""
        self._consecutive_failures = 0
        if self._state == CircuitState.HALF_OPEN:
            self._consecutive_successes += 1
            if self._consecutive_successes >= self.half_open_success_threshold:
                self._state = CircuitState.CLOSED
                self._consecutive_successes = 0
                self._last_state_change = time.time()

    def _handle_primary_failure(
        self, route: RPKIRouteAnnouncement, current_time: float, reason: str
    ) -> RPKIFallbackResult:
        """Handle failure from primary validator, updating failure counts and checking trip condition."""
        self._consecutive_failures += 1
        self._last_failure_time = current_time

        if self._state == CircuitState.HALF_OPEN:
            # Immediate re-trip on single failure during half-open
            self._trip(current_time)
        elif self._state == CircuitState.CLOSED and self._consecutive_failures >= self.failure_threshold:
            self._trip(current_time)

        return self._execute_fallback(route, current_time, f"{reason} (consecutive_failures={self._consecutive_failures})")

    def _trip(self, current_time: float):
        """Trip circuit to OPEN state."""
        self._state = CircuitState.OPEN
        self._trip_count += 1
        self._last_state_change = current_time
        self._consecutive_successes = 0

    def _execute_fallback(
        self, route: RPKIRouteAnnouncement, current_time: float, reason: str
    ) -> RPKIFallbackResult:
        """Execute secondary fallback validation or conservative fail-safe."""
        self._fallback_invocations += 1

        if self.secondary_validator is not None:
            try:
                secondary_res = self.secondary_validator(route)
                if secondary_res in (RPKIValidationState.VALID, RPKIValidationState.NOT_FOUND):
                    return RPKIFallbackResult(
                        route=route,
                        validation_state=secondary_res,
                        circuit_state=self._state,
                        policy_applied=FallbackPolicy.FALLBACK_SECONDARY_RTR,
                        routed=True,
                        fallback_engaged=True,
                        diagnostic=f"Routed via Secondary RTR validator: {reason}",
                    )
                else:
                    return RPKIFallbackResult(
                        route=route,
                        validation_state=secondary_res,
                        circuit_state=self._state,
                        policy_applied=FallbackPolicy.FALLBACK_SECONDARY_RTR,
                        routed=False,
                        fallback_engaged=True,
                        diagnostic=f"Dropped by Secondary RTR validator: {reason}",
                    )
            except Exception:
                pass

        # Failsafe conservative policy: allow NOT_FOUND, avoid total blackhole
        return RPKIFallbackResult(
            route=route,
            validation_state=RPKIValidationState.NOT_FOUND,
            circuit_state=self._state,
            policy_applied=FallbackPolicy.FAILSAFE_CONSERVATIVE,
            routed=True,
            fallback_engaged=True,
            diagnostic=f"Routed via FAILSAFE_CONSERVATIVE: {reason}",
        )

    def reset(self):
        """Manually reset the circuit breaker to clean CLOSED state."""
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._last_state_change = time.time()

    def get_metrics(self) -> Dict[str, Any]:
        """Return diagnostic metrics."""
        return {
            "state": self._state.value,
            "consecutive_failures": self._consecutive_failures,
            "consecutive_successes": self._consecutive_successes,
            "trip_count": self._trip_count,
            "total_evaluated": self._total_evaluated,
            "fallback_invocations": self._fallback_invocations,
            "recovery_timeout_sec": self.recovery_timeout_sec,
        }
