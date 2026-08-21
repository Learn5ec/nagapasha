"""Tests for the Strategist agent (Stage 5)."""

import pytest
from unittest.mock import MagicMock

from nagapasha.models.request_model import ParameterModel, RequestModel
from nagapasha.stages.stage05_strategist import (
    _default_candidates,
    _guess_attack_class,
    run_strategist,
)


def _make_param(name, location="query", param_type="free_text", value="test",
                do_not_fuzz=False):
    return ParameterModel(
        name=name,
        location=location,
        inferred_type=param_type,
        raw_value=value,
        is_fuzz_target=True,
        do_not_fuzz=do_not_fuzz,
    )


def _make_request(params=None):
    if params is None:
        params = [
            _make_param("id", "query", "int", "42"),
            _make_param("file", "query", "filename", "report.pdf"),
            _make_param("X-User-Id", "header", "int", "100"),
        ]
    return RequestModel(
        method="GET",
        url="https://example.com/api/item",
        base_url="https://example.com",
        headers={"X-User-Id": "100"},
        query_params={"id": "42", "file": "report.pdf"},
        parameters=params,
    )


class TestGuessAttackClass:
    def test_path_param_lfi(self):
        param = _make_param("file", "path", "filename", "report.pdf")
        assert _guess_attack_class(param) == "path_traversal"

    def test_sql_keywords(self):
        param = _make_param("id", "query", "int", "42")
        assert _guess_attack_class(param) == "sql_injection"

    def test_user_header_idor(self):
        param = _make_param("X-User-Id", "header", "int", "100")
        assert _guess_attack_class(param) == "idor"

    def test_file_keyword_lfi(self):
        """File keyword in query with PHP tech stack should suggest LFI."""
        param = _make_param("file", "query", "filename", "doc.pdf")
        assert _guess_attack_class(param, confirmed_tech_stack={"language": "php"}) == "lfi"

    def test_file_keyword_path_traversal(self):
        """File keyword in query without PHP should suggest path traversal."""
        param = _make_param("file", "query", "filename", "doc.pdf")
        assert _guess_attack_class(param) == "path_traversal"

    def test_free_text_xss(self):
        param = _make_param("q", "query", "free_text", "test")
        assert _guess_attack_class(param) == "xss"

    def test_default_generic(self):
        param = _make_param("foo", "query", "date", "2024-01-01")
        assert _guess_attack_class(param) == "generic_injection"


class TestDefaultCandidates:
    def test_skips_auth_params(self):
        """Auth params (do_not_fuzz=True) should not get candidates."""
        param = _make_param("Authorization", "header", "free_text", "Bearer xyz",
                            do_not_fuzz=True)
        req = _make_request(params=[param])
        candidates = _default_candidates(req, {})
        assert len(candidates) == 0

    def test_includes_fuzz_targets(self):
        """Fuzz targets should get candidates."""
        req = _make_request()
        candidates = _default_candidates(req, {})
        assert len(candidates) == 3  # id, file, X-User-Id

    def test_candidate_shape(self):
        req = _make_request()
        candidates = _default_candidates(req, {})
        c = candidates[0]
        assert "parameter_index" in c
        assert "attack_class" in c
        assert "confidence" in c
        assert "wstg_reference" in c


class TestRunStrategist:
    def test_fallback_on_runner_failure(self):
        """Should fall back to defaults when runner raises."""
        req = _make_request()
        runner = MagicMock()
        runner.invoke.side_effect = Exception("claude not available")

        candidates = run_strategist(req, runner=runner)
        assert len(candidates) > 0

    def test_fallback_on_bad_response(self):
        """Should fall back to defaults on bad response."""
        req = _make_request()
        runner = MagicMock()
        runner.invoke.return_value = {"status": "error", "data": []}

        candidates = run_strategist(req, runner=runner)
        assert len(candidates) > 0

    def test_accepts_valid_response(self):
        """Should accept valid LLM response."""
        req = _make_request()
        runner = MagicMock()
        runner.invoke.return_value = {
            "status": "ok",
            "data": [
                {
                    "parameter_index": 0,
                    "attack_class": "sql_injection",
                    "rationale": "id param is query int",
                    "confidence": "high",
                    "wstg_reference": "WSTG-INPV-08",
                    "recommended_payload_tags": ["sqli_union"],
                    "parameter_name": "id",
                    "parameter_type": "int",
                }
            ],
        }

        candidates = run_strategist(req, runner=runner)
        assert len(candidates) == 1
        assert candidates[0]["attack_class"] == "sql_injection"
