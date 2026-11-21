"""
Ingress Gateway Traffic Telemetry & Upstream Latency Anomaly Diagnostic for RouteKernel.
Collects latency percentiles, tracks status code distributions, computes EWMA z-score anomaly
spikes, and exports standard Prometheus exposition format.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import math
import time
from typing import Dict, List, Optional, Tuple


@dataclass
class AnomalyEvent:
    timestamp: float
    upstream_target: str
    observed_latency_ms: float
    baseline_mean_ms: float
    z_score: float
    severity: str
    message: str


class TrafficTelemetry:
    """
    Real-time routing traffic telemetry rotary with statistical anomaly detection.
    """

    def __init__(
        self,
        window_size: int = 1000,
        ewma_alpha: float = 0.1,
        z_score_threshold: float = 3.0,
        min_samples_for_anomaly: int = 20,
    ):
        self.window_size = max(10, window_size)
        self.ewma_alpha = max(0.01, min(0.99, ewma_alpha))
        self.z_score_threshold = z_score_threshold
        self.min_samples = min_samples_for_anomaly

        self.total_requests = 0
        self.status_codes: Dict[int, int] = {}
        self.upstream_requests: Dict[str, int] = {}
        self.upstream_errors: Dict[str, int] = {}

        # Upstream target -> sliding window of latency_ms
        self.latency_windows: Dict[str, deque[float]] = {}
        # Upstream target -> EWMA state
        self.ewma_latencies: Dict[str, float] = {}

        self.anomalies: List[AnomalyEvent] = []

    def record_request(
        self,
        upstream_target: str,
        status_code: int,
        latency_ms: float,
        timestamp: Optional[float] = None,
    ) -> Optional[AnomalyEvent]:
        """
        Records a routed request outcome and analyzes for statistical latency anomalies.
        """
        ts = timestamp if timestamp is not None else time.time()
        lat = max(0.0, float(latency_ms))

        self.total_requests += 1
        self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1
        self.upstream_requests[upstream_target] = self.upstream_requests.get(upstream_target, 0) + 1

        if status_code >= 500 or status_code == 0:
            self.upstream_errors[upstream_target] = self.upstream_errors.get(upstream_target, 0) + 1

        if upstream_target not in self.latency_windows:
            self.latency_windows[upstream_target] = deque(maxlen=self.window_size)
            self.ewma_latencies[upstream_target] = lat

        window = self.latency_windows[upstream_target]

        anomaly: Optional[AnomalyEvent] = None

        # Anomaly Detection before updating window
        if len(window) >= self.min_samples:
            mean = sum(window) / len(window)
            variance = sum((x - mean) ** 2 for x in window) / (len(window) - 1)
            raw_std_dev = math.sqrt(variance)
            # Guard against zero variance dividing by zero: use floor of 5% mean or 0.1ms
            std_dev = max(raw_std_dev, 0.05 * mean, 0.1)

            z = (lat - mean) / std_dev
            if z >= self.z_score_threshold:
                sev = "CRITICAL" if z >= 4.5 else "WARNING"
                anomaly = AnomalyEvent(
                    timestamp=ts,
                    upstream_target=upstream_target,
                    observed_latency_ms=round(lat, 2),
                    baseline_mean_ms=round(mean, 2),
                    z_score=round(z, 2),
                    severity=sev,
                    message=f"Latency spike detected on {upstream_target}: {lat:.1f}ms vs baseline {mean:.1f}ms (z={z:.2f})",
                )
                self.anomalies.append(anomaly)

        # Update statistics
        window.append(lat)
        prev_ewma = self.ewma_latencies[upstream_target]
        self.ewma_latencies[upstream_target] = (self.ewma_alpha * lat) + ((1.0 - self.ewma_alpha) * prev_ewma)

        return anomaly

    def get_percentiles(self, upstream_target: Optional[str] = None) -> Dict[str, float]:
        """
        Computes p50, p90, p99 latencies for a target or across all recorded latencies.
        """
        samples: List[float] = []
        if upstream_target:
            if upstream_target in self.latency_windows:
                samples = list(self.latency_windows[upstream_target])
        else:
            for w in self.latency_windows.values():
                samples.extend(w)

        if not samples:
            return {"p50": 0.0, "p90": 0.0, "p99": 0.0, "max": 0.0}

        sorted_samples = sorted(samples)
        n = len(sorted_samples)

        def pct(p: float) -> float:
            idx = min(n - 1, max(0, int(math.ceil((p / 100.0) * n)) - 1))
            return round(sorted_samples[idx], 2)

        return {
            "p50": pct(50),
            "p90": pct(90),
            "p99": pct(99),
            "max": round(sorted_samples[-1], 2),
        }

    def export_prometheus(self, service: str = "routekernel") -> str:
        """
        Generates standard Prometheus exposition text format.
        """
        lines = [
            f"# HELP routekernel_requests_total Total HTTP requests routed through kernel",
            f"# TYPE routekernel_requests_total counter",
            f'routekernel_requests_total{{service="{service}"}} {self.total_requests}',
            f"# HELP routekernel_upstream_errors_total Total 5xx or connection failures per upstream",
            f"# TYPE routekernel_upstream_errors_total counter",
        ]

        for target, errors in self.upstream_errors.items():
            lines.append(f'routekernel_upstream_errors_total{{service="{service}",upstream="{target}"}} {errors}')

        pcts = self.get_percentiles()
        lines.extend([
            f"# HELP routekernel_latency_ms Latency percentiles in milliseconds",
            f"# TYPE routekernel_latency_ms gauge",
            f'routekernel_latency_ms{{service="{service}",quantile="0.50"}} {pcts["p50"]}',
            f'routekernel_latency_ms{{service="{service}",quantile="0.90"}} {pcts["p90"]}',
            f'routekernel_latency_ms{{service="{service}",quantile="0.99"}} {pcts["p99"]}',
            f"# HELP routekernel_anomalies_total Total statistical latency anomalies triggered",
            f"# TYPE routekernel_anomalies_total counter",
            f'routekernel_anomalies_total{{service="{service}"}} {len(self.anomalies)}',
        ])

        for code, count in self.status_codes.items():
            lines.append(f'routekernel_http_status_total{{service="{service}",status="{code}"}} {count}')

        return "\n".join(lines) + "\n"
