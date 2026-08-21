"""Tests for the Specialist agent (Stage 11)."""

import pytest
from unittest.mock import MagicMock

from nagapasha.stages.stage11_specialist import (
    _heuristic_analysis,
    run_specialist,
)


class TestHeuristicAnalysis:
    def test_consistent_status_changes_confirmed(self):
        """Consistent status changes for same param should be confirmed."""
        near_misses = [
            {"parameter_name": "id", "payload": "1", "status_code": 200, "response_time": 0.1},
            {"parameter_name": "id", "payload": "2", "status_code": 403, "response_time": 0.1},
            {"parameter_name": "id", "payload": "3", "status_code": 500, "response_time": 0.1},
        ]
        verdicts = _heuristic_analysis(near_misses)
        assert len(verdicts) >= 1
        assert verdicts[0]["verdict"] == "confirmed"
        assert "status changes" in verdicts[0]["evidence"].lower()

    def test_response_time_spike_confirmed(self):
        """Response time spikes should be confirmed."""
        near_misses = [
            {"parameter_name": "id", "payload": "1", "status_code": 200, "response_time": 3.0},
            {"parameter_name": "id", "payload": "2", "status_code": 200, "response_time": 4.0},
            {"parameter_name": "id", "payload": "3", "status_code": 200, "response_time": 3.5},
        ]
        verdicts = _heuristic_analysis(near_misses)
        assert len(verdicts) >= 1
        assert verdicts[0]["verdict"] == "confirmed"
        assert "response time" in verdicts[0]["evidence"].lower()

    def test_error_signature_confirmed(self):
        """Error signatures should be confirmed."""
        near_misses = [
            {"parameter_name": "id", "payload": "' OR 1=1", "status_code": 200,
             "response_time": 0.1, "notes": "MySQL error detected"},
            {"parameter_name": "id", "payload": "' AND 1=1", "status_code": 200,
             "response_time": 0.1, "notes": "Syntax error in response"},
        ]
        verdicts = _heuristic_analysis(near_misses)
        assert len(verdicts) >= 1
        assert verdicts[0]["verdict"] == "confirmed"
        assert "error" in verdicts[0]["evidence"].lower()

    def test_inconclusive_no_pattern(self):
        """No consistent pattern should be inconclusive."""
        near_misses = [
            {"parameter_name": "id", "payload": "1", "status_code": 200, "response_time": 0.1},
            {"parameter_name": "id", "payload": "2", "status_code": 200, "response_time": 0.1},
        ]
        verdicts = _heuristic_analysis(near_misses)
        assert len(verdicts) >= 1
        assert verdicts[0]["verdict"] == "inconclusive"

    def test_empty_near_misses(self):
        """Empty near-misses should return empty list."""
        verdicts = _heuristic_analysis([])
        assert verdicts == []


class TestRunSpecialist:
    def test_fallback_on_runner_failure(self):
        """Should fall back to heuristics when runner fails."""
        near_misses = [
            {"parameter_name": "id", "payload": "1", "status_code": 200, "response_time": 0.1},
            {"parameter_name": "id", "payload": "2", "status_code": 200, "response_time": 0.1},
        ]
        runner = MagicMock()
        runner.invoke.side_effect = Exception("claude not available")

        verdicts = run_specialist(near_misses, runner=runner)
        assert len(verdicts) >= 1

    def test_accepts_llm_response(self):
        """Should accept valid LLM response."""
        near_misses = [
            {"parameter_name": "id", "payload": "1", "status_code": 200, "response_time": 0.1},
            {"parameter_name": "id", "payload": "2", "status_code": 200, "response_time": 0.1},
        ]
        runner = MagicMock()
        runner.invoke.return_value = {
            "status": "ok",
            "data": [
                {
                    "parameter_name": "id",
                    "payload": "1",
                    "verdict": "confirmed",
                    "evidence": {
                        "status_delta": {"from": 200, "to": 500},
                        "timing_delta": {"from": 0.1, "to": 0.5},
                    },
                    "recommendation": "Manual review",
                }
            ],
        }

        verdicts = run_specialist(near_misses, runner=runner)
        assert len(verdicts) == 1
        assert verdicts[0]["verdict"] == "confirmed"

    def test_empty_near_misses_returns_empty(self):
        """Empty near-misses should return empty list."""
        verdicts = run_specialist([])
        assert verdicts == []
