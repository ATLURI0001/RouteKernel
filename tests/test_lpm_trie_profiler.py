from scripts.lpm_trie_profiler import LpmTrieProfiler


def test_lpm_longest_prefix_match():
    trie = LpmTrieProfiler()
    trie.insert("0.0.0.0/0", "gw-default")
    trie.insert("10.0.0.0/8", "gw-ten")
    trie.insert("10.20.0.0/16", "gw-specific")

    assert trie.lookup("192.168.1.1") == "gw-default"
    assert trie.lookup("10.1.2.3") == "gw-ten"
    assert trie.lookup("10.20.5.5") == "gw-specific"


def test_lpm_benchmark():
    trie = LpmTrieProfiler()
    trie.insert("10.0.0.0/8", "gw-1")
    trie.insert("172.16.0.0/12", "gw-2")
    ips = ["10.1.1.1", "172.16.5.4", "8.8.8.8"]

    res = trie.run_benchmark(ips, iterations=20)
    assert res.route_count == 2
    assert res.p50_microseconds >= 0.0
    assert res.throughput_lookups_sec > 0.0
