import pytest
from scripts.traffic_telemetry import TrafficTelemetry

def test_traffic_telemetry_recording_and_percentiles():
    telemetry = TrafficTelemetry(window_size=100)

    for i in range(1, 101):
        telemetry.record_request("upstream-auth", 200, float(i))

    assert telemetry.total_requests == 100
    assert telemetry.status_codes[200] == 100
    assert telemetry.upstream_requests["upstream-auth"] == 100

    pcts = telemetry.get_percentiles("upstream-auth")
    assert pcts["p50"] == 50.0
    assert pcts["p90"] == 90.0
    assert pcts["p99"] == 99.0
    assert pcts["max"] == 100.0


def test_traffic_telemetry_anomaly_detection_spike():
    telemetry = TrafficTelemetry(window_size=100, min_samples_for_anomaly=25, z_score_threshold=3.0)

    # Establish baseline around 20ms with low variance
    for _ in range(30):
        telemetry.record_request("upstream-payment", 200, 20.0)

    # Sudden high latency spike
    anomaly = telemetry.record_request("upstream-payment", 200, 250.0)
    assert anomaly is not None
    assert anomaly.severity == "CRITICAL"
    assert anomaly.z_score > 3.0
    assert len(telemetry.anomalies) == 1
    assert "Latency spike detected" in anomaly.message


def test_traffic_telemetry_error_tracking():
    telemetry = TrafficTelemetry()

    telemetry.record_request("upstream-billing", 200, 15.0)
    telemetry.record_request("upstream-billing", 502, 35.0)
    telemetry.record_request("upstream-billing", 504, 5000.0)

    assert telemetry.upstream_errors["upstream-billing"] == 2
    assert telemetry.status_codes[502] == 1
    assert telemetry.status_codes[504] == 1


def test_traffic_telemetry_prometheus_export():
    telemetry = TrafficTelemetry()
    telemetry.record_request("upstream-orders", 200, 25.0)
    telemetry.record_request("upstream-orders", 500, 150.0)

    text = telemetry.export_prometheus("routekernel-prod")
    assert 'routekernel_requests_total{service="routekernel-prod"} 2' in text
    assert 'routekernel_upstream_errors_total{service="routekernel-prod",upstream="upstream-orders"} 1' in text
    assert 'routekernel_http_status_total{service="routekernel-prod",status="200"} 1' in text
    assert 'routekernel_http_status_total{service="routekernel-prod",status="500"} 1' in text
    assert 'routekernel_latency_ms{service="routekernel-prod",quantile="0.50"}' in text
