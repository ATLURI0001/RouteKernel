"""Tests for IPv4 Longest Prefix Match (LPM) Radix Trie & Benchmark Profiler."""

import pytest
from scripts.lpm_trie_router import (
    IPv4RadixTrieRouter,
    LinearCIDRRouter,
    ip_to_uint32,
    parse_cidr,
    run_routing_benchmark,
)


def test_ip_and_cidr_parsing() -> None:
    # Valid conversions
    assert ip_to_uint32("0.0.0.0") == 0
    assert ip_to_uint32("255.255.255.255") == 0xFFFFFFFF
    assert ip_to_uint32("192.168.1.1") == (192 << 24) | (168 << 16) | (1 << 8) | 1

    # Invalid IPs
    with pytest.raises(ValueError, match="Invalid IPv4"):
        ip_to_uint32("192.168.1.256")
    with pytest.raises(ValueError, match="Invalid IPv4"):
        ip_to_uint32("not-an-ip")

    # CIDR mask checks
    p_int, p_len = parse_cidr("10.0.0.0/8")
    assert p_len == 8
    assert p_int == (10 << 24)

    # Host bits masking normalization (e.g. 192.168.1.55/24 -> 192.168.1.0/24)
    p_int2, p_len2 = parse_cidr("192.168.1.55/24")
    assert p_len2 == 24
    assert p_int2 == (192 << 24) | (168 << 16) | (1 << 8)

    with pytest.raises(ValueError, match="Invalid CIDR mask length"):
        parse_cidr("10.0.0.0/33")


def test_radix_trie_longest_prefix_match() -> None:
    trie = IPv4RadixTrieRouter()

    # Insert nested hierarchy
    trie.insert("0.0.0.0/0", "gw-default")
    trie.insert("10.0.0.0/8", "gw-corp-net")
    trie.insert("10.1.0.0/16", "gw-dc-east")
    trie.insert("10.1.2.0/24", "gw-k8s-pod")
    trie.insert("10.1.2.4/32", "gw-ingress-vip")
    trie.insert("172.16.0.0/12", "gw-staging")

    assert len(trie) == 6

    # Test exact VIP match (/32)
    vip_route = trie.lookup("10.1.2.4")
    assert vip_route is not None
    assert vip_route.gateway == "gw-ingress-vip"

    # Test pod subnet (/24)
    pod_route = trie.lookup("10.1.2.99")
    assert pod_route is not None
    assert pod_route.gateway == "gw-k8s-pod"

    # Test datacenter subnet (/16)
    dc_route = trie.lookup("10.1.99.5")
    assert dc_route is not None
    assert dc_route.gateway == "gw-dc-east"

    # Test broad corp (/8)
    corp_route = trie.lookup("10.50.1.1")
    assert corp_route is not None
    assert corp_route.gateway == "gw-corp-net"

    # Test staging (/12)
    staging_route = trie.lookup("172.20.5.1")
    assert staging_route is not None
    assert staging_route.gateway == "gw-staging"

    # Test default fallback (/0)
    inet_route = trie.lookup("8.8.8.8")
    assert inet_route is not None
    assert inet_route.gateway == "gw-default"


def test_radix_trie_delete_and_pruning() -> None:
    trie = IPv4RadixTrieRouter()
    trie.insert("10.0.0.0/8", "gw-10")
    trie.insert("10.1.0.0/16", "gw-10-1")

    assert len(trie) == 2

    # Delete /16
    deleted = trie.delete("10.1.0.0/16")
    assert deleted is True
    assert len(trie) == 1

    # Lookup should now fall back to /8
    route = trie.lookup("10.1.5.5")
    assert route is not None
    assert route.gateway == "gw-10"

    # Delete non-existent
    assert trie.delete("192.168.1.0/24") is False


def test_trie_linear_parity_and_benchmark() -> None:
    trie = IPv4RadixTrieRouter()
    linear = LinearCIDRRouter()

    rules = [
        ("0.0.0.0/0", "gw-default"),
        ("10.0.0.0/8", "gw-10"),
        ("10.1.0.0/16", "gw-10-1"),
        ("192.168.0.0/16", "gw-lan"),
        ("192.168.1.0/24", "gw-lan-sub1"),
        ("172.16.0.0/12", "gw-dmz"),
    ]

    for cidr, gw in rules:
        trie.insert(cidr, gw)
        linear.insert(cidr, gw)

    test_ips = [
        "10.1.0.5",
        "10.5.5.5",
        "192.168.1.100",
        "192.168.20.1",
        "172.18.0.1",
        "1.1.1.1",
    ]

    # Verify identical lookup results
    for ip in test_ips:
        r_trie = trie.lookup(ip)
        r_lin = linear.lookup(ip)
        assert r_trie is not None
        assert r_lin is not None
        assert r_trie.gateway == r_lin.gateway

    # Run benchmark profile
    bench = run_routing_benchmark(trie, linear, test_ips, iterations=2000)
    assert bench["iterations"] == 2000
    assert bench["route_table_size"] == 6
    assert bench["trie_lookups_per_sec"] > 0
    assert bench["speedup_factor"] > 0
