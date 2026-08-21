"""Tests for the Fitter agent (Stage 8)."""

import pytest

from nagapasha.models.request_model import ParameterModel
from nagapasha.stages.stage08_fitter import (
    _heuristic_fit,
    apply_placement,
    run_fitter,
)


def _make_param(name, location="query", param_type="free_text", value="test"):
    return ParameterModel(
        name=name,
        location=location,
        inferred_type=param_type,
        raw_value=value,
        is_fuzz_target=True,
        do_not_fuzz=False,
    )


class TestHeuristicFit:
    def test_query_sqli_glue(self):
        """SQLi payloads in query params should get quote glue."""
        param = _make_param("id", "query", "int", "42")
        result = _heuristic_fit(param, "sql_injection", "' OR 1=1")
        assert result["glue_string"] == "'"
        assert result["placement_mode"] == "full_replace"

    def test_query_xss_encoding(self):
        """XSS payloads in query params should get URL encoding."""
        param = _make_param("search", "query", "free_text", "test")
        result = _heuristic_fit(param, "xss", "<script>alert(1)</script>")
        assert result["encoding"] == "url"

    def test_path_lfi_glue(self):
        """Path traversal payloads should get path glue."""
        param = _make_param("file", "path", "filename", "report.pdf")
        result = _heuristic_fit(param, "lfi", "../../../etc/passwd")
        assert result["placement_mode"] == "path_segment"
        assert result["glue_string"] == "/"

    def test_path_lfi_no_glue(self):
        """Non-dotdot path traversal should not get glue."""
        param = _make_param("file", "path", "filename", "report.pdf")
        result = _heuristic_fit(param, "lfi", "etc/passwd")
        assert result["glue_string"] == ""

    def test_json_field_value(self):
        """JSON body params should get json_field_value placement."""
        param = _make_param("data", "body_json", "free_text", "test")
        result = _heuristic_fit(param, "sqli", "' OR 1=1")
        assert result["placement_mode"] == "json_field_value"

    def test_header_value(self):
        """Header params should get header_value placement."""
        param = _make_param("X-Custom", "header", "free_text", "test")
        result = _heuristic_fit(param, "xss", "<script>")
        assert result["placement_mode"] == "header_value"

    def test_cookie_url_encoding(self):
        """Cookie params should get URL encoding."""
        param = _make_param("session", "cookie", "free_text", "abc123")
        result = _heuristic_fit(param, "xss", "<script>")
        assert result["encoding"] == "url"


class TestApplyPlacement:
    def test_query_full_replace(self):
        """Full replace should update query param value."""
        param = _make_param("id", "query", "int", "42")
        placement = {"placement_mode": "full_replace", "glue_string": ""}
        url = "https://example.com/api?id=42"
        result = apply_placement(url, param, placement, "999")
        assert "id=999" in result
        assert "id=42" not in result

    def test_query_prefix(self):
        """Prefix should prepend to query param value."""
        param = _make_param("search", "query", "free_text", "test")
        placement = {"placement_mode": "prefix", "glue_string": "'"}
        url = "https://example.com/api?search=test"
        result = apply_placement(url, param, placement, "OR 1=1")
        # _prefix_query_param prepends glue+payload to existing value
        assert "search=" in result
        assert "test" in result

    def test_unknown_placement_returns_base(self):
        """Unknown placement mode should return base URL unchanged."""
        param = _make_param("id", "query", "int", "42")
        placement = {"placement_mode": "unknown_mode", "glue_string": ""}
        url = "https://example.com/api?id=42"
        result = apply_placement(url, param, placement, "999")
        assert result == url


class TestRunFitter:
    def test_fallback_without_runner(self):
        """Should use heuristic fitting when no runner provided."""
        param = _make_param("id", "query", "int", "42")
        result = run_fitter(param, "sql_injection", "' OR 1=1")
        assert result["placement_mode"] in (
            "full_replace", "prefix", "suffix", "wrap",
            "json_field_value", "header_value", "path_segment",
        )
        assert "rationale" in result

    def test_accepts_valid_llm_response(self):
        """Should accept valid LLM response when runner succeeds."""
        from unittest.mock import MagicMock

        param = _make_param("id", "query", "int", "42")
        runner = MagicMock()
        runner.invoke.return_value = {
            "status": "ok",
            "data": {
                "parameter_name": "id",
                "parameter_location": "query",
                "placement_mode": "prefix",
                "encoding": "none",
                "glue_string": "'",
                "pre_separator": "",
                "post_separator": "",
                "rationale": "SQLi needs quote glue",
            },
        }

        result = run_fitter(param, "sql_injection", "' OR 1=1", runner=runner)
        assert result["placement_mode"] == "prefix"
        assert result["glue_string"] == "'"
