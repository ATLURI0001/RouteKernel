"""
RouteKernel: Upstream Circuit Breaker & Adaptive Health Probe Rotary.
Implements a 3-state resilience circuit breaker with consecutive failure tripping,
exponential cooldown backoff, and canary probe verification.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Callable, Optional, TypeVar, Any, Dict

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when an execution call is rejected because the circuit is open."""

    def __init__(self, message: str, cooldown_remaining_sec: float):
        super().__init__(message)
        self.cooldown_remaining_sec = max(0.0, cooldown_remaining_sec)


class UpstreamCircuitBreaker:
    """
    Guards upstream services against cascading overload by tripping on repeated failures
    and validating recovery via canary probes.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_sec: float = 10.0,
        canary_success_threshold: int = 2,
        max_recovery_timeout_sec: float = 120.0,
        backoff_multiplier: float = 2.0,
    ):
        if failure_threshold <= 0:
            raise ValueError("failure_threshold must be greater than zero")
        if recovery_timeout_sec <= 0:
            raise ValueError("recovery_timeout_sec must be positive")
        if canary_success_threshold <= 0:
            raise ValueError("canary_success_threshold must be greater than zero")

        self.failure_threshold = failure_threshold
        self.base_recovery_timeout_sec = recovery_timeout_sec
        self.current_recovery_timeout_sec = recovery_timeout_sec
        self.canary_success_threshold = canary_success_threshold
        self.max_recovery_timeout_sec = max_recovery_timeout_sec
        self.backoff_multiplier = backoff_multiplier

        self._state: CircuitState = CircuitState.CLOSED
        self._consecutive_failures: int = 0
        self._consecutive_canary_successes: int = 0
        self._last_state_change: float = time.time()
        self._last_failure_time: Optional[float] = None
        self._trip_count: int = 0
        self._total_calls: int = 0

    @property
    def state(self) -> CircuitState:
        self._evaluate_state_transition()
        return self._state

    def _evaluate_state_transition(self) -> None:
        """Transitions OPEN to HALF_OPEN when the recovery cooldown expires."""
        if self._state == CircuitState.OPEN:
            elapsed = time.time() - self._last_state_change
            if elapsed >= self.current_recovery_timeout_sec:
                self._state = CircuitState.HALF_OPEN
                self._consecutive_canary_successes = 0
                self._last_state_change = time.time()

    def allow_request(self) -> bool:
        """Checks if a request is permitted under the current circuit state."""
        self._evaluate_state_transition()

        if self._state == CircuitState.CLOSED:
            return True

        if self._state == CircuitState.HALF_OPEN:
            # In half-open, permit canary probes up to threshold
            return True

        # OPEN state: reject
        return False

    def record_success(self) -> None:
        """Records a successful execution."""
        self._total_calls += 1
        self._evaluate_state_transition()

        if self._state == CircuitState.HALF_OPEN:
            self._consecutive_canary_successes += 1
            if self._consecutive_canary_successes >= self.canary_success_threshold:
                # Fully recovered!
                self._state = CircuitState.CLOSED
                self._consecutive_failures = 0
                self._consecutive_canary_successes = 0
                self.current_recovery_timeout_sec = self.base_recovery_timeout_sec
                self._last_state_change = time.time()
        elif self._state == CircuitState.CLOSED:
            self._consecutive_failures = 0

    def record_failure(self) -> None:
        """Records a failed execution."""
        self._total_calls += 1
        now = time.time()
        self._last_failure_time = now

        if self._state == CircuitState.CLOSED:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold:
                # Trip to OPEN
                self._trip_circuit(now)
        elif self._state == CircuitState.HALF_OPEN:
            # Canary probe failed: immediately trip back to OPEN with backoff
            self.current_recovery_timeout_sec = min(
                self.max_recovery_timeout_sec,
                self.current_recovery_timeout_sec * self.backoff_multiplier,
            )
            self._trip_circuit(now)

    def _trip_circuit(self, now: float) -> None:
        self._state = CircuitState.OPEN
        self._last_state_change = now
        self._consecutive_canary_successes = 0
        self._trip_count += 1

    def execute(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Executes func protected by the circuit breaker."""
        if not self.allow_request():
            remaining = max(
                0.0,
                self.current_recovery_timeout_sec - (time.time() - self._last_state_change),
            )
            raise CircuitOpenError(
                f"Circuit is OPEN. Cooldown remaining: {remaining:.2f}s",
                cooldown_remaining_sec=remaining,
            )

        try:
            result = func(*args, **kwargs)
            self.record_success()
            return result
        except Exception:
            self.record_failure()
            raise

    def get_telemetry(self) -> Dict[str, Any]:
        """Returns current operational telemetry snapshot."""
        self._evaluate_state_transition()
        remaining = 0.0
        if self._state == CircuitState.OPEN:
            remaining = max(
                0.0,
                self.current_recovery_timeout_sec - (time.time() - self._last_state_change),
            )

        return {
            "state": self._state.value,
            "consecutive_failures": self._consecutive_failures,
            "consecutive_canary_successes": self._consecutive_canary_successes,
            "trip_count": self._trip_count,
            "total_calls": self._total_calls,
            "cooldown_remaining_sec": round(remaining, 3),
            "current_recovery_timeout_sec": self.current_recovery_timeout_sec,
        }

    def reset(self) -> None:
        """Resets the circuit breaker to clean closed state."""
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._consecutive_canary_successes = 0
        self.current_recovery_timeout_sec = self.base_recovery_timeout_sec
        self._last_state_change = time.time()
        self._last_failure_time = None
