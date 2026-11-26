from scripts.bgp_flap_damping_sentinel import (
    BgpFlapDampingSentinel,
    RouteState,
)


def test_single_flap_accumulation():
    sentinel = BgpFlapDampingSentinel(suppress_threshold=3000.0, penalty_per_flap=1000.0)
    rep = sentinel.record_flap("198.51.100.0/24", "192.0.2.1", now=1000.0)

    assert rep.state == RouteState.UNSUPPRESSED
    assert rep.current_penalty == 1000.0
    assert rep.total_flaps == 1
    assert rep.incident_flagged is False


def test_consecutive_flaps_trigger_suppression():
    sentinel = BgpFlapDampingSentinel(suppress_threshold=2500.0, penalty_per_flap=1000.0)
    prefix = "203.0.113.0/24"
    peer = "192.0.2.1"

    sentinel.record_flap(prefix, peer, now=1000.0)
    sentinel.record_flap(prefix, peer, now=1005.0)
    rep3 = sentinel.record_flap(prefix, peer, now=1010.0)

    assert rep3.state == RouteState.SUPPRESSED
    assert rep3.suppression_active is True
    assert rep3.incident_flagged is True
    assert rep3.current_penalty >= 2500.0


def test_exponential_decay_and_reuse():
    # half_life = 100 seconds, suppress = 2500, reuse = 750
    sentinel = BgpFlapDampingSentinel(
        suppress_threshold=2500.0,
        reuse_threshold=750.0,
        half_life_seconds=100.0,
    )
    prefix = "10.0.0.0/8"
    peer = "10.254.0.1"

    # Trip suppression with 3 flaps
    for t in [100.0, 101.0, 102.0]:
        sentinel.record_flap(prefix, peer, now=t)

    assert sentinel.evaluate_route(prefix, peer, now=102.0) == RouteState.SUPPRESSED

    # After 1 half-life (100s elapsed at t=202): penalty drops from ~3000 to ~1500 (> 750)
    assert sentinel.evaluate_route(prefix, peer, now=202.0) == RouteState.SUPPRESSED

    # After 3 half-lives (300s elapsed at t=402): penalty drops from ~3000 to ~375 (<= 750)
    assert sentinel.evaluate_route(prefix, peer, now=402.0) == RouteState.UNSUPPRESSED


def test_max_suppression_window():
    sentinel = BgpFlapDampingSentinel(
        suppress_threshold=1000.0,
        max_suppress_seconds=500.0,
        half_life_seconds=10000.0,  # Very slow decay
    )
    prefix = "172.16.0.0/12"
    peer = "172.16.255.1"

    sentinel.record_flap(prefix, peer, now=100.0)
    assert sentinel.evaluate_route(prefix, peer, now=100.0) == RouteState.SUPPRESSED

    # At t=650 (> 500s elapsed since suppression start): route should unsuppress
    assert sentinel.evaluate_route(prefix, peer, now=650.0) == RouteState.UNSUPPRESSED
