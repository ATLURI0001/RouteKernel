"""Tests for Shortest Path First (SPF) Routing Convergence Benchmark Profiler."""

import pytest
from scripts.spf_benchmark_profiler import (
    SpfBenchmarkProfiler,
    dijkstra_heap,
    dijkstra_linear,
    generate_topology,
)


def test_dijkstra_correctness():
    # Construct a known 5-node weighted graph
    # 0 -> 1 (w=4), 0 -> 2 (w=2)
    # 2 -> 1 (w=1), 2 -> 3 (w=8), 2 -> 4 (w=10)
    # 1 -> 3 (w=5)
    # 3 -> 4 (w=2)
    graph = {
        0: [(1, 4.0), (2, 2.0)],
        1: [(0, 4.0), (2, 1.0), (3, 5.0)],
        2: [(0, 2.0), (1, 1.0), (3, 8.0), (4, 10.0)],
        3: [(1, 5.0), (2, 8.0), (4, 2.0)],
        4: [(2, 10.0), (3, 2.0)],
    }

    dist_linear = dijkstra_linear(graph, source=0)
    dist_heap = dijkstra_heap(graph, source=0)

    # Shortest paths from 0:
    # 0: 0.0
    # 1: 0 -> 2 -> 1 = 3.0
    # 2: 0 -> 2 = 2.0
    # 3: 0 -> 2 -> 1 -> 3 = 8.0
    # 4: 0 -> 2 -> 1 -> 3 -> 4 = 10.0
    expected = {0: 0.0, 1: 3.0, 2: 2.0, 3: 8.0, 4: 10.0}

    assert dist_linear == expected
    assert dist_heap == expected
    assert dist_linear == dist_heap


def test_generate_topology():
    for top_type in ["mesh", "ring", "spine_leaf"]:
        g = generate_topology(node_count=10, topology_type=top_type, seed=123)
        assert len(g) == 10
        # All nodes have at least one adjacency
        for u, adj in g.items():
            assert len(adj) >= 1
            for v, w in adj:
                assert w > 0.0


def test_profile_scale():
    profiler = SpfBenchmarkProfiler(iterations=5, seed=42)
    res = profiler.profile_scale(node_count=20, topology_type="mesh")

    assert res.node_count == 20
    assert res.edge_count > 0
    assert res.heap_p50_ms > 0
    assert res.heap_p99_ms >= res.heap_p50_ms
    assert res.iterations == 5
    assert len(profiler.results) == 1


def test_run_benchmark_matrix_and_markdown():
    profiler = SpfBenchmarkProfiler(iterations=3, seed=99)
    matrix = profiler.run_benchmark_matrix(scales=[15, 30])

    assert len(matrix) == 2
    assert matrix[0].node_count == 15
    assert matrix[1].node_count == 30

    report = profiler.generate_markdown_report()
    assert "| Nodes (V) | Edges (E) |" in report
    assert "| 15 |" in report
    assert "| 30 |" in report
    assert "Convergence SLA" in report
