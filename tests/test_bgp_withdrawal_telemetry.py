"""Tests for BGP Prefix Withdrawal Velocity & Convergence Latency Telemetry Rotary."""

import pytest
from scripts.bgp_withdrawal_telemetry import (
    BGPWithdrawalTelemetryRotary,
    ConvergenceLatencyStats,
    RotaryTelemetrySummary,
    WithdrawalAlertLevel,
    WithdrawalEvent,
    WithdrawalRateSnapshot,
)


def test_rotary_initial_state():
    rotary = BGPWithdrawalTelemetryRotary()
    snap = rotary.get_rate_snapshot(window_sec=60.0, now=1000.0)

    assert snap.total_withdrawals == 0
    assert snap.velocity_per_sec == 0.0
    assert snap.affected_prefixes == 0
    assert snap.affected_peers == 0
    assert snap.affected_asns == 0
    assert snap.alert_level == WithdrawalAlertLevel.NORMAL

    stats = rotary.compute_latency_stats()
    assert stats.sample_count == 0
    assert stats.mean_ms == 0.0


def test_rotary_record_withdrawal_and_sliding_window():
    rotary = BGPWithdrawalTelemetryRotary(
        elevated_threshold_per_sec=5.0,
        critical_threshold_per_sec=15.0,
        storm_threshold_per_sec=30.0,
    )
    t0 = 1000.0

    # Record 6 events within 1 second for AS65001 across different prefixes
    for i in range(6):
        rotary.record_withdrawal(
            peer_ip="192.0.2.1",
            asn=65001,
            prefix=f"10.0.{i}.0/24",
            timestamp=t0 + (i * 0.1),
            convergence_duration_ms=45.0 + i,
        )

    # 5s window has 6 events -> 6 / 5 = 1.2 w/s -> NORMAL
    snap5 = rotary.get_rate_snapshot(window_sec=5.0, now=t0 + 1.0)
    assert snap5.total_withdrawals == 6
    assert snap5.affected_prefixes == 6
    assert snap5.affected_peers == 1
    assert snap5.affected_asns == 1
    assert snap5.alert_level == WithdrawalAlertLevel.NORMAL

    # 1s window has 6 events -> 6 / 1 = 6.0 w/s -> ELEVATED (threshold is 5.0)
    snap1 = rotary.get_rate_snapshot(window_sec=1.0, now=t0 + 1.0)
    assert snap1.total_withdrawals == 6
    assert snap1.velocity_per_sec == 6.0
    assert snap1.alert_level == WithdrawalAlertLevel.ELEVATED


def test_rotary_alert_level_escalations():
    rotary = BGPWithdrawalTelemetryRotary(
        elevated_threshold_per_sec=2.0,
        critical_threshold_per_sec=5.0,
        storm_threshold_per_sec=10.0,
    )
    t0 = 1000.0

    # Ingest 12 events within 1 second -> 12 w/s -> STORM (threshold 10.0)
    for i in range(12):
        rotary.record_withdrawal(
            peer_ip="198.51.100.1",
            asn=64512,
            prefix=f"172.16.{i}.0/24",
            timestamp=t0 + (i * 0.05),
        )

    snap = rotary.get_rate_snapshot(window_sec=1.0, now=t0 + 1.0)
    assert snap.total_withdrawals == 12
    assert snap.velocity_per_sec == 12.0
    assert snap.alert_level == WithdrawalAlertLevel.STORM


def test_rotary_latency_percentiles():
    rotary = BGPWithdrawalTelemetryRotary()
    t0 = 1000.0

    # Ingest latencies: 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 ms
    for i in range(1, 11):
        lat = float(i * 10)
        rotary.record_withdrawal(
            peer_ip="203.0.113.1",
            asn=13335,
            prefix="1.1.1.0/24",
            timestamp=t0 + i,
            convergence_duration_ms=lat,
        )

    stats = rotary.compute_latency_stats()
    assert stats.sample_count == 10
    assert stats.min_ms == 10.0
    assert stats.max_ms == 100.0
    assert stats.mean_ms == 55.0
    assert stats.p50_ms == 55.0
    assert stats.p90_ms == 91.0
    assert stats.p99_ms == 99.1


def test_rotary_buffer_capacity_eviction():
    rotary = BGPWithdrawalTelemetryRotary(buffer_capacity=100)
    t0 = 1000.0

    # Insert 150 events
    for i in range(150):
        rotary.record_withdrawal(
            peer_ip=f"10.0.0.{i % 10}",
            asn=65000 + (i % 5),
            prefix=f"10.{i}.0.0/16",
            timestamp=t0 + i,
            convergence_duration_ms=10.0,
        )

    assert rotary._total_recorded == 150
    assert len(rotary._ring) == 100
    assert len(rotary._latencies) == 100


def test_rotary_markdown_report_rendering():
    rotary = BGPWithdrawalTelemetryRotary()
    rotary.record_withdrawal("192.0.2.1", 65001, "10.1.0.0/16", timestamp=1000.0, convergence_duration_ms=25.0)
    rotary.record_withdrawal("198.51.100.2", 65002, "10.2.0.0/16", timestamp=1001.0, convergence_duration_ms=35.0)

    report = rotary.format_markdown_report(now=1002.0)
    assert "# BGP Prefix Withdrawal Velocity & Convergence Rotary" in report
    assert "**Total Recorded Events** | `2`" in report
    assert "**AS65001**: 1 withdrawals" in report
    assert "**AS65002**: 1 withdrawals" in report
    assert "`192.0.2.1`: 1 withdrawals" in report
