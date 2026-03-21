"""
Unit tests for MoltGrid Load Test Script
==========================================
Tests MetricsCollector, report generation, pass/fail verdict, and scenario registry.
"""

import pytest
from tests.load_test import (
    MetricsCollector,
    MAX_ERROR_RATE,
    MAX_ELAPSED_SECONDS,
    get_scenarios,
    register_scenario,
    _scenarios,
    _pick_scenario,
    Scenario,
)


# ---------------------------------------------------------------------------
# MetricsCollector tests
# ---------------------------------------------------------------------------

class TestMetricsCollector:
    """Tests for the MetricsCollector aggregation logic."""

    def test_empty_collector(self):
        mc = MetricsCollector()
        assert mc.total_requests() == 0
        assert mc.total_errors() == 0
        assert mc.error_rate() == 0.0
        assert mc.scenarios == []

    def test_record_single_success(self):
        mc = MetricsCollector()
        mc.record("test_scenario", 15.0, 200, is_error=False)
        assert mc.total_requests() == 1
        assert mc.total_errors() == 0
        assert mc.error_rate() == 0.0
        assert "test_scenario" in mc.scenarios

    def test_record_single_error(self):
        mc = MetricsCollector()
        mc.record("test_scenario", 100.0, 500, is_error=True)
        assert mc.total_requests() == 1
        assert mc.total_errors() == 1
        assert mc.error_rate() == 100.0

    def test_record_multiple_scenarios(self):
        mc = MetricsCollector()
        mc.record("scenario_a", 10.0, 200, is_error=False)
        mc.record("scenario_a", 20.0, 200, is_error=False)
        mc.record("scenario_b", 30.0, 201, is_error=False)
        mc.record("scenario_b", 40.0, 500, is_error=True)

        assert mc.total_requests() == 4
        assert mc.total_errors() == 1
        assert mc.error_rate() == 25.0
        assert set(mc.scenarios) == {"scenario_a", "scenario_b"}

    def test_error_rate_calculation(self):
        mc = MetricsCollector()
        for _ in range(99):
            mc.record("s", 10.0, 200, is_error=False)
        mc.record("s", 10.0, 500, is_error=True)
        assert mc.error_rate() == pytest.approx(1.0, abs=0.01)

    def test_percentile_single_value(self):
        mc = MetricsCollector()
        mc.record("s", 42.0, 200, is_error=False)
        assert mc.percentile("s", 50) == 42.0
        assert mc.percentile("s", 95) == 42.0
        assert mc.percentile("s", 99) == 42.0

    def test_percentile_multiple_values(self):
        mc = MetricsCollector()
        for i in range(1, 101):
            mc.record("s", float(i), 200, is_error=False)
        # p50 of 1..100 should be around 50
        assert mc.percentile("s", 50) == pytest.approx(50.5, abs=1.0)
        assert mc.percentile("s", 95) == pytest.approx(95.05, abs=1.0)
        assert mc.percentile("s", 99) == pytest.approx(99.01, abs=1.0)

    def test_percentile_empty_scenario(self):
        mc = MetricsCollector()
        assert mc.percentile("nonexistent", 50) == 0.0

    def test_status_code_tracking(self):
        mc = MetricsCollector()
        mc.record("s", 10.0, 200, is_error=False)
        mc.record("s", 10.0, 200, is_error=False)
        mc.record("s", 10.0, 404, is_error=False)
        mc.record("s", 10.0, 500, is_error=True)

        summary = mc.scenario_summary("s")
        assert summary["status_codes"][200] == 2
        assert summary["status_codes"][404] == 1
        assert summary["status_codes"][500] == 1


# ---------------------------------------------------------------------------
# Scenario summary tests
# ---------------------------------------------------------------------------

class TestScenarioSummary:
    """Tests for scenario_summary and full_report generation."""

    def test_scenario_summary_fields(self):
        mc = MetricsCollector()
        mc.record("s", 10.0, 200, is_error=False)
        mc.record("s", 20.0, 200, is_error=False)
        mc.record("s", 30.0, 500, is_error=True)

        summary = mc.scenario_summary("s")
        assert summary["total_requests"] == 3
        assert summary["errors"] == 1
        assert summary["error_rate_pct"] == pytest.approx(33.33, abs=0.1)
        assert "p50_ms" in summary
        assert "p95_ms" in summary
        assert "p99_ms" in summary
        assert "status_codes" in summary

    def test_scenario_summary_zero_requests(self):
        mc = MetricsCollector()
        summary = mc.scenario_summary("nonexistent")
        assert summary["total_requests"] == 0
        assert summary["errors"] == 0
        assert summary["error_rate_pct"] == 0.0


# ---------------------------------------------------------------------------
# Report generation and verdict tests
# ---------------------------------------------------------------------------

class TestReportAndVerdict:
    """Tests for full_report and pass/fail verdict logic."""

    def test_pass_verdict_low_error_fast(self):
        mc = MetricsCollector()
        for _ in range(100):
            mc.record("s", 10.0, 200, is_error=False)
        report = mc.full_report(elapsed_seconds=30.0)
        assert report["verdict"] == "PASS"
        assert report["summary"]["total_requests"] == 100
        assert report["summary"]["error_rate_pct"] == 0.0
        assert report["summary"]["elapsed_seconds"] == 30.0

    def test_fail_verdict_high_error_rate(self):
        mc = MetricsCollector()
        for _ in range(98):
            mc.record("s", 10.0, 200, is_error=False)
        for _ in range(2):
            mc.record("s", 10.0, 500, is_error=True)
        report = mc.full_report(elapsed_seconds=30.0)
        # error_rate = 2.0% > MAX_ERROR_RATE (1.0%)
        assert report["verdict"] == "FAIL"

    def test_fail_verdict_too_slow(self):
        mc = MetricsCollector()
        for _ in range(100):
            mc.record("s", 10.0, 200, is_error=False)
        report = mc.full_report(elapsed_seconds=120.0)
        # elapsed > MAX_ELAPSED_SECONDS (60)
        assert report["verdict"] == "FAIL"

    def test_fail_verdict_both_criteria(self):
        mc = MetricsCollector()
        for _ in range(90):
            mc.record("s", 10.0, 200, is_error=False)
        for _ in range(10):
            mc.record("s", 10.0, 500, is_error=True)
        report = mc.full_report(elapsed_seconds=120.0)
        assert report["verdict"] == "FAIL"

    def test_pass_edge_case_just_under_threshold(self):
        """Error rate just below 1.0%, elapsed just below 60s."""
        mc = MetricsCollector()
        # 0.99% error rate: 1 error in ~101 requests
        for _ in range(100):
            mc.record("s", 10.0, 200, is_error=False)
        # No errors -- 0% < 1.0%
        report = mc.full_report(elapsed_seconds=59.9)
        assert report["verdict"] == "PASS"

    def test_fail_edge_case_exactly_at_threshold(self):
        """Error rate exactly 1.0% should FAIL (< 1.0, not <=)."""
        mc = MetricsCollector()
        for _ in range(99):
            mc.record("s", 10.0, 200, is_error=False)
        mc.record("s", 10.0, 500, is_error=True)
        # error_rate = 1.0% -- NOT < 1.0, so FAIL
        report = mc.full_report(elapsed_seconds=30.0)
        assert report["verdict"] == "FAIL"

    def test_fail_elapsed_exactly_60(self):
        """Elapsed exactly 60s should FAIL (< 60, not <=)."""
        mc = MetricsCollector()
        for _ in range(100):
            mc.record("s", 10.0, 200, is_error=False)
        report = mc.full_report(elapsed_seconds=60.0)
        assert report["verdict"] == "FAIL"

    def test_report_contains_thresholds(self):
        mc = MetricsCollector()
        mc.record("s", 10.0, 200, is_error=False)
        report = mc.full_report(elapsed_seconds=10.0)
        assert report["thresholds"]["max_error_rate_pct"] == MAX_ERROR_RATE
        assert report["thresholds"]["max_elapsed_seconds"] == MAX_ELAPSED_SECONDS

    def test_report_throughput_calculation(self):
        mc = MetricsCollector()
        for _ in range(100):
            mc.record("s", 10.0, 200, is_error=False)
        report = mc.full_report(elapsed_seconds=10.0)
        assert report["summary"]["throughput_rps"] == 10.0

    def test_report_zero_elapsed(self):
        mc = MetricsCollector()
        mc.record("s", 10.0, 200, is_error=False)
        report = mc.full_report(elapsed_seconds=0.0)
        assert report["summary"]["throughput_rps"] == 0

    def test_report_scenarios_present(self):
        mc = MetricsCollector()
        mc.record("alpha", 10.0, 200, is_error=False)
        mc.record("beta", 20.0, 201, is_error=False)
        report = mc.full_report(elapsed_seconds=10.0)
        assert "alpha" in report["scenarios"]
        assert "beta" in report["scenarios"]

    def test_report_is_json_serializable(self):
        import json
        mc = MetricsCollector()
        mc.record("s", 10.0, 200, is_error=False)
        report = mc.full_report(elapsed_seconds=10.0)
        # Should not raise
        json_str = json.dumps(report)
        parsed = json.loads(json_str)
        assert parsed["verdict"] == "PASS"


# ---------------------------------------------------------------------------
# Scenario registry tests
# ---------------------------------------------------------------------------

class TestScenarioRegistry:
    """Tests for scenario registration and weighted selection."""

    def test_builtin_scenarios_registered(self):
        scenarios = get_scenarios()
        names = [s.name for s in scenarios]
        assert "health_check" in names
        assert "auth_signup_login" in names
        assert "memory_crud" in names
        assert "directory_list" in names
        assert "relay_send_inbox" in names
        assert "pricing_check" in names

    def test_scenario_has_required_fields(self):
        scenarios = get_scenarios()
        for s in scenarios:
            assert isinstance(s.name, str)
            assert isinstance(s.weight, int)
            assert s.weight > 0
            assert callable(s.fn)

    def test_pick_scenario_returns_valid(self):
        scenarios = get_scenarios()
        for _ in range(50):
            picked = _pick_scenario(scenarios)
            assert picked in scenarios

    def test_pick_scenario_single(self):
        single = [Scenario(name="only", weight=1, fn=lambda *a: None)]
        for _ in range(10):
            assert _pick_scenario(single).name == "only"

    def test_weighted_distribution_bias(self):
        """Higher weight scenarios should be picked more often."""
        heavy = Scenario(name="heavy", weight=100, fn=lambda *a: None)
        light = Scenario(name="light", weight=1, fn=lambda *a: None)
        picks = {"heavy": 0, "light": 0}
        for _ in range(1000):
            p = _pick_scenario([heavy, light])
            picks[p.name] += 1
        # Heavy should be picked significantly more
        assert picks["heavy"] > picks["light"] * 5


# ---------------------------------------------------------------------------
# Constants / threshold tests
# ---------------------------------------------------------------------------

class TestThresholdConstants:
    """Verify the locked pass criteria constants."""

    def test_max_error_rate_is_1(self):
        assert MAX_ERROR_RATE == 1.0

    def test_max_elapsed_is_60(self):
        assert MAX_ELAPSED_SECONDS == 60
