from scripts.route_latency_profiler import profile_route_latency


def test_route_latency_profiler():
    result = profile_route_latency(["/api/v1", "/api/v2"], rounds=10)
    assert result["total_chars"] == 140
    assert result["elapsed_s"] >= 0
