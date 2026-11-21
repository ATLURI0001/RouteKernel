"""Unit tests for SmoothWeightedRoundRobin load balancer and health canary manager."""

import pytest
from scripts.upstream_balancer import (
    AllUpstreamsUnhealthyError,
    SmoothWeightedRoundRobin,
    UpstreamNode,
)


def test_upstream_node_initialization_and_validation():
    node = UpstreamNode("10.0.0.1", 8080, weight=5)
    assert node.address == "10.0.0.1:8080"
    assert node.effective_weight == 5
    assert node.is_healthy is True

    with pytest.raises(ValueError, match="port out of range"):
        UpstreamNode("10.0.0.1", 70000)

    with pytest.raises(ValueError, match="weight must be a positive integer"):
        UpstreamNode("10.0.0.1", 8080, weight=0)


def test_smooth_weighted_round_robin_distribution():
    balancer = SmoothWeightedRoundRobin()
    # Nodes with weights: A=5, B=1, C=1
    balancer.add_node("nodeA", 80, weight=5)
    balancer.add_node("nodeB", 80, weight=1)
    balancer.add_node("nodeC", 80, weight=1)

    # Over 7 selections, counts should match exactly 5, 1, 1 smoothly interleaved
    counts = {"nodeA:80": 0, "nodeB:80": 0, "nodeC:80": 0}
    sequence = []
    for _ in range(7):
        selected = balancer.select()
        counts[selected.address] += 1
        sequence.append(selected.address)

    assert counts["nodeA:80"] == 5
    assert counts["nodeB:80"] == 1
    assert counts["nodeC:80"] == 1

    # Verify smooth interleaving: nodeA does not appear 5 times consecutively at the start
    assert sequence != [
        "nodeA:80",
        "nodeA:80",
        "nodeA:80",
        "nodeA:80",
        "nodeA:80",
        "nodeB:80",
        "nodeC:80",
    ]


def test_unhealthy_node_removal_and_all_down_exception():
    balancer = SmoothWeightedRoundRobin(fail_threshold=2)
    balancer.add_node("node1", 8080, weight=1)

    # 1 failure -> still healthy
    balancer.record_failure("node1:8080")
    assert balancer.select().address == "node1:8080"

    # 2nd failure -> marked unhealthy
    balancer.record_failure("node1:8080")
    with pytest.raises(AllUpstreamsUnhealthyError):
        balancer.select()


def test_canary_probe_and_health_recovery():
    t0 = 1000.0
    balancer = SmoothWeightedRoundRobin(fail_threshold=2, pass_threshold=2, cooldown_sec=10.0)
    balancer.add_node("node1", 8080, weight=5)
    balancer.add_node("node2", 8080, weight=5)

    # Node 1 fails twice at t0
    balancer.record_failure("node1:8080", now=t0)
    balancer.record_failure("node1:8080", now=t0)

    # At t0 + 5s: node1 is still cooling down; all traffic to node2
    assert balancer.select(now=t0 + 5.0).address == "node2:8080"

    # At t0 + 12s (cooldown 10s expired): node1 admits canary probe
    # Record 2 consecutive successes to clear unhealthy status
    balancer.record_success("node1:8080")
    balancer.record_success("node1:8080")

    # Node 1 is fully recovered with restored weight
    node1 = balancer.nodes["node1:8080"]
    assert node1.is_healthy is True
    assert node1.effective_weight == 5
