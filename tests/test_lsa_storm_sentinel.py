"""
Unit and regression test suite for OSPF LSA Flooding Storm Failsafe Sentinel.
"""

import pytest
from scripts.lsa_storm_sentinel import (
    LSAAction,
    LSAHeader,
    LSAStormSentinel,
    LSAType,
    LSAViolationCode,
)


def make_lsa(
    router_id: str = "192.168.1.1",
    link_state_id: str = "10.0.0.1",
    seq: int = 0x80000001,
    lsa_type: LSAType = LSAType.ROUTER,
) -> LSAHeader:
    return LSAHeader(
        lsa_type=lsa_type,
        link_state_id=link_state_id,
        advertising_router=router_id,
        sequence_number=seq,
        checksum=0x1234,
        age_seconds=10,
    )


def test_nominal_lsa_admission():
    sentinel = LSAStormSentinel(min_ls_arrival_sec=1.0)
    lsa1 = make_lsa(seq=0x80000001)

    res = sentinel.inspect_lsa(lsa1, current_time=100.0)
    assert res.action == LSAAction.ACCEPTED
    assert res.violation_code is None

    # Next LSA after 1.5s (nominal)
    lsa2 = make_lsa(seq=0x80000002)
    res2 = sentinel.inspect_lsa(lsa2, current_time=101.5)
    assert res2.action == LSAAction.ACCEPTED


def test_malformed_lsa_rejection():
    sentinel = LSAStormSentinel()
    bad_lsa = LSAHeader(
        lsa_type=LSAType.ROUTER,
        link_state_id="",
        advertising_router="",
        sequence_number=0x80000001,
        checksum=0,
    )

    res = sentinel.inspect_lsa(bad_lsa, current_time=100.0)
    assert res.action == LSAAction.SUPPRESSED
    assert res.violation_code == LSAViolationCode.MALFORMED_LSA


def test_min_ls_arrival_breach():
    sentinel = LSAStormSentinel(min_ls_arrival_sec=1.0)

    lsa1 = make_lsa(seq=0x80000001)
    res1 = sentinel.inspect_lsa(lsa1, current_time=100.0)
    assert res1.action == LSAAction.ACCEPTED

    # Arriving 0.3s later (rapid flap / storm) -> Breach!
    lsa2 = make_lsa(seq=0x80000002)
    res2 = sentinel.inspect_lsa(lsa2, current_time=100.3)
    assert res2.action == LSAAction.SUPPRESSED
    assert res2.violation_code == LSAViolationCode.MIN_LS_ARRIVAL_BREACH


def test_stale_or_duplicate_sequence_number():
    sentinel = LSAStormSentinel(min_ls_arrival_sec=1.0)

    lsa1 = make_lsa(seq=0x80000005)
    sentinel.inspect_lsa(lsa1, current_time=100.0)

    # Identical sequence number arriving later
    lsa_dup = make_lsa(seq=0x80000005)
    res_dup = sentinel.inspect_lsa(lsa_dup, current_time=102.0)
    assert res_dup.action == LSAAction.SUPPRESSED
    assert res_dup.violation_code == LSAViolationCode.STALE_SEQUENCE_NUMBER

    # Stale smaller sequence number arriving
    lsa_stale = make_lsa(seq=0x80000004)
    res_stale = sentinel.inspect_lsa(lsa_stale, current_time=104.0)
    assert res_stale.action == LSAAction.SUPPRESSED
    assert res_stale.violation_code == LSAViolationCode.STALE_SEQUENCE_NUMBER


def test_lsa_storm_detection_and_quarantine():
    sentinel = LSAStormSentinel(
        min_ls_arrival_sec=0.1,
        max_lsas_per_window=5,
        rate_window_sec=5.0,
        quarantine_duration_sec=20.0,
    )

    router = "10.254.0.1"

    # Send 5 LSAs within 1 second (under ceiling of 5)
    for i in range(5):
        lsa = make_lsa(router_id=router, link_state_id=f"10.0.{i}.1", seq=0x80000001 + i)
        res = sentinel.inspect_lsa(lsa, current_time=100.0 + (i * 0.15))
        assert res.action == LSAAction.ACCEPTED

    # 6th LSA breaches window ceiling (5 LSAs in 5s) -> Storm quarantine triggered!
    lsa_storm = make_lsa(router_id=router, link_state_id="10.0.99.1", seq=0x80000010)
    res_storm = sentinel.inspect_lsa(lsa_storm, current_time=101.0)
    assert res_storm.action == LSAAction.QUARANTINED
    assert res_storm.violation_code == LSAViolationCode.STORM_RATE_EXCEEDED

    # Any subsequent LSA from this router is rejected while in quarantine
    lsa_blocked = make_lsa(router_id=router, link_state_id="10.0.50.1", seq=0x80000020)
    res_blocked = sentinel.inspect_lsa(lsa_blocked, current_time=110.0)
    assert res_blocked.action == LSAAction.QUARANTINED
    assert res_blocked.violation_code == LSAViolationCode.QUARANTINED_ADVERTISER

    # After quarantine duration expires (101.0 + 20.0 = 121.0)
    res_recovered = sentinel.inspect_lsa(lsa_blocked, current_time=122.0)
    assert res_recovered.action == LSAAction.ACCEPTED


def test_manual_release_and_telemetry():
    sentinel = LSAStormSentinel(
        min_ls_arrival_sec=0.1,
        max_lsas_per_window=2,
        quarantine_duration_sec=30.0,
    )

    router = "172.16.1.1"
    for i in range(3):
        lsa = make_lsa(router_id=router, link_state_id=f"10.0.{i}.1", seq=0x80000001 + i)
        sentinel.inspect_lsa(lsa, current_time=200.0 + (i * 0.2))

    # Should be quarantined
    assert sentinel.advertisers[router].quarantine_until > 200.0
    assert sentinel.release_quarantine(router) is True
    assert sentinel.advertisers[router].quarantine_until == 0.0

    telem = sentinel.get_telemetry()
    assert telem["total_processed"] == 3
    assert telem["incidents_logged"] == 1


def test_postmortem_report_generation():
    sentinel = LSAStormSentinel(
        min_ls_arrival_sec=0.1,
        max_lsas_per_window=2,
        quarantine_duration_sec=30.0,
    )

    assert "No OSPF LSA Storms Detected" in sentinel.generate_postmortem_report()

    router = "192.168.100.1"
    for i in range(3):
        lsa = make_lsa(router_id=router, link_state_id=f"192.168.100.{i}", seq=0x80000001 + i)
        sentinel.inspect_lsa(lsa, current_time=300.0 + (i * 0.15))

    report = sentinel.generate_postmortem_report()
    assert "Incident Postmortem: OSPF LSA Flooding Storm Mitigation Report" in report
    assert "192.168.100.1" in report
    assert "Storm Incident Timeline" in report
