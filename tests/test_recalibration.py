"""Tests for continuous recalibration (Stage 9.5)."""

import pytest

from nagapasha.engine.recalibration import (
    RecalibrationChecker,
    check_baseline_drift,
)


class TestRecalibrationChecker:
    def test_initial_state(self):
        """Test initial recalibration state."""
        checker = RecalibrationChecker(
            rate_limit_pps=4.0,
            max_requests=100,
        )
        assert checker.state.total_requests == 0
        assert not checker.needs_baseline_refresh()

    def test_check_result_tracks_requests(self):
        """Test that check_result tracks request count."""
        checker = RecalibrationChecker()

        checker.check_result({"status_code": 200})
        checker.check_result({"status_code": 404})

        assert checker.state.total_requests == 2

    def test_403_ratio(self):
        """Test 403 ratio calculation."""
        checker = RecalibrationChecker()

        # Add some 403 responses
        for _ in range(10):
            checker.check_result({"status_code": 403})

        # Add some 200 responses
        for _ in range(10):
            checker.check_result({"status_code": 200})

        ratio = checker.get_403_ratio()
        assert 0.4 <= ratio <= 0.6  # Should be around 50%

    def test_needs_baseline_refresh(self):
        """Test baseline refresh flag."""
        checker = RecalibrationChecker()

        # Initially not needed (total_requests=0 < BASELINE_REFRESH_INTERVAL)
        assert checker.needs_baseline_refresh() == False

        # After enough requests, needs refresh
        for i in range(100):
            checker.check_result({"status_code": 200})

        assert checker.needs_baseline_refresh() == True

    def test_needs_control_request(self):
        """Test control request flag."""
        checker = RecalibrationChecker()

        assert checker.needs_control_request() == False

        # After some requests
        for i in range(50):
            checker.check_result({"status_code": 200})

        assert checker.needs_control_request() == True

    def test_get_stats(self):
        """Test stats retrieval."""
        checker = RecalibrationChecker()

        checker.check_result({"status_code": 200})
        checker.check_result({"status_code": 403})

        stats = checker.get_stats()
        assert stats["total_requests"] == 2
        assert "403_ratio" in stats

    def test_check_max_requests(self):
        """Test max requests limit."""
        checker = RecalibrationChecker(max_requests=5)

        for i in range(5):
            checker.check_result({"status_code": 200})

        assert checker.check_max_requests() == True


class TestCheckBaselineDrift:
    def test_no_drift(self):
        """Test no drift when baselines are consistent."""
        baseline = {"content_length": 1000}
        baselines = [
            {"content_length": 1000},
            {"content_length": 1005},
            {"content_length": 995},
        ]

        assert check_baseline_drift(baseline, baselines) == False

    def test_drift_detected(self):
        """Test drift detection."""
        baseline = {"content_length": 2000}
        baselines = [
            {"content_length": 1000},
            {"content_length": 1005},
            {"content_length": 995},
        ]

        assert check_baseline_drift(baseline, baselines) == True

    def test_insufficient_baselines(self):
        """Test drift check with insufficient baselines."""
        baseline = {"content_length": 1000}
        baselines = [{"content_length": 1000}]

        assert check_baseline_drift(baseline, baselines) == False
