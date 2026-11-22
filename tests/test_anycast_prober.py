"""Unit tests for Anycast PoP Health Prober and Geo-DNS Failover Rotary Engine."""

import unittest
from scripts.anycast_prober import AnycastFailoverRotary, ProbeResult


class TestAnycastFailoverRotary(unittest.TestCase):
    def setUp(self) -> None:
        self.rotary = AnycastFailoverRotary(
            failure_threshold=3,
            recovery_threshold=2,
            max_latency_ms=300.0,
        )
        self.rotary.register_pop("pop-iad", "us-east", "198.51.100.1", weight=100)
        self.rotary.register_pop("pop-sfo", "us-west", "198.51.100.2", weight=100)
        self.rotary.register_pop("pop-fra", "eu-west", "198.51.100.3", weight=100)

    def test_register_pop_validation(self) -> None:
        with self.assertRaises(ValueError):
            self.rotary.register_pop("", "us-east", "1.1.1.1")
        with self.assertRaises(ValueError):
            self.rotary.register_pop("pop-test", "", "1.1.1.1")
        with self.assertRaises(ValueError):
            self.rotary.register_pop("pop-test", "us-east", "1.1.1.1", weight=0)

    def test_flap_damping_and_health_transitions(self) -> None:
        # 1. First probe failure: stays healthy due to damping
        res1 = self.rotary.record_probe(
            ProbeResult("pop-iad", timestamp=100.0, latency_ms=45.0, success=False, status_code=500)
        )
        self.assertTrue(res1)
        self.assertEqual(self.rotary.pops["pop-iad"].consecutive_failures, 1)

        # 2. Second failure: still healthy
        res2 = self.rotary.record_probe(
            ProbeResult("pop-iad", timestamp=101.0, latency_ms=45.0, success=False, status_code=500)
        )
        self.assertTrue(res2)

        # 3. Third failure: hits threshold 3 -> flips to UNHEALTHY
        res3 = self.rotary.record_probe(
            ProbeResult("pop-iad", timestamp=102.0, latency_ms=45.0, success=False, status_code=500)
        )
        self.assertFalse(res3)
        self.assertFalse(self.rotary.pops["pop-iad"].healthy)

        # 4. Single recovery success: not enough to restore health
        rec1 = self.rotary.record_probe(
            ProbeResult("pop-iad", timestamp=103.0, latency_ms=25.0, success=True, status_code=200)
        )
        self.assertFalse(rec1)

        # 5. Second recovery success: hits threshold 2 -> restored to HEALTHY
        rec2 = self.rotary.record_probe(
            ProbeResult("pop-iad", timestamp=104.0, latency_ms=22.0, success=True, status_code=200)
        )
        self.assertTrue(rec2)
        self.assertTrue(self.rotary.pops["pop-iad"].healthy)

    def test_latency_threshold_breach_counts_as_failure(self) -> None:
        # Latency of 400ms exceeds max_latency_ms (300ms)
        self.rotary.record_probe(
            ProbeResult("pop-iad", timestamp=100.0, latency_ms=450.0, success=True, status_code=200)
        )
        node = self.rotary.pops["pop-iad"]
        self.assertEqual(node.consecutive_failures, 1)

    def test_optimal_pop_selection_and_regional_failover(self) -> None:
        # Both healthy: us-east client selects local pop-iad
        pop = self.rotary.select_optimal_pop("us-east")
        self.assertIsNotNone(pop)
        self.assertEqual(pop.pop_id, "pop-iad")

        # Induce 3 consecutive failures on pop-iad
        for i in range(3):
            self.rotary.record_probe(
                ProbeResult("pop-iad", timestamp=100.0 + i, latency_ms=50.0, success=False)
            )

        # Local pop-iad is down -> failover to nearest us-west (pop-sfo)
        failover_pop = self.rotary.select_optimal_pop("us-east")
        self.assertIsNotNone(failover_pop)
        self.assertEqual(failover_pop.pop_id, "pop-sfo")

    def test_total_mesh_blackout_returns_none(self) -> None:
        # Fail all PoPs
        for pop_id in ["pop-iad", "pop-sfo", "pop-fra"]:
            for i in range(3):
                self.rotary.record_probe(
                    ProbeResult(pop_id, timestamp=100.0 + i, latency_ms=50.0, success=False)
                )

        optimal = self.rotary.select_optimal_pop("us-east")
        self.assertIsNone(optimal)

    def test_health_report_and_reset(self) -> None:
        self.rotary.record_probe(
            ProbeResult("pop-iad", timestamp=100.0, latency_ms=20.0, success=True)
        )
        report = self.rotary.get_health_report()
        self.assertEqual(report["total_pops"], 3)
        self.assertEqual(report["healthy_pops"], 3)
        self.assertEqual(report["overall_availability_pct"], 100.0)

        self.rotary.reset()
        self.assertEqual(len(self.rotary.pops), 0)


if __name__ == "__main__":
    unittest.main()
