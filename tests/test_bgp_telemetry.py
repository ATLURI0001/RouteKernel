"""Tests for BGP Route Flap Telemetry & Convergence Diagnostic."""

import time
import pytest
from scripts.bgp_telemetry import (
    BGPTelemetryCollector,
    PeerConvergenceSnapshot,
    RouteHealthStatus,
)


def test_bgp_telemetry_initial_state_and_announcement():
    collector = BGPTelemetryCollector(half_life_sec=30.0)
    snap = collector.record_update("198.51.100.1", "10.0.0.0/24", is_withdrawal=False, timestamp=1000.0)

    assert snap.peer_ip == "198.51.100.1"
    assert snap.total_announcements == 1
    assert snap.total_withdrawals == 0
    assert snap.status == RouteHealthStatus.CONVERGED
    assert snap.current_penalty == 500.0


def test_bgp_telemetry_flap_suppression_and_decay():
    # Suppress threshold 1800, half_life 60s
    collector = BGPTelemetryCollector(
        suppress_threshold=1800.0,
        reuse_threshold=800.0,
        half_life_sec=60.0,
        penalty_per_withdrawal=1000.0,
    )
    t0 = 1000.0

    # Two rapid withdrawals: 1000 + 1000 = 2000 penalty -> SUPPRESSED
    collector.record_update("198.51.100.2", "172.16.0.0/16", is_withdrawal=True, timestamp=t0)
    snap2 = collector.record_update("198.51.100.2", "172.16.0.0/16", is_withdrawal=True, timestamp=t0 + 1.0)

    assert snap2.status == RouteHealthStatus.SUPPRESSED
    assert snap2.current_penalty >= 1900.0

    # After 60 seconds (1 half-life), penalty decays by 50% -> ~1000 -> UNSTABLE
    snapDecayed = collector.get_peer_snapshot("198.51.100.2", now=t0 + 61.0)
    assert snapDecayed.status == RouteHealthStatus.UNSTABLE
    assert snapDecayed.current_penalty < 1500.0

    # After 180 seconds (3 half-lives), penalty decays to ~250 -> CONVERGED
    snapRecovered = collector.get_peer_snapshot("198.51.100.2", now=t0 + 181.0)
    assert snapRecovered.status == RouteHealthStatus.CONVERGED
    assert snapRecovered.current_penalty < 800.0


def test_bgp_telemetry_format_markdown_report():
    collector = BGPTelemetryCollector()
    collector.record_update("192.0.2.1", "192.168.1.0/24", is_withdrawal=False, timestamp=1000.0)
    collector.record_update("192.0.2.2", "192.168.2.0/24", is_withdrawal=True, timestamp=1000.0)

    report = collector.format_markdown_report(now=1000.0)
    assert "### BGP Route Convergence & Flap Diagnostic Report" in report
    assert "`192.0.2.1`" in report
    assert "`192.0.2.2`" in report
    assert "CONVERGED" in report
