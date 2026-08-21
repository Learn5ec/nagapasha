"""Tests for the targeting stage."""

import pytest

from nagapasha.models.request_model import ParameterModel, RequestModel
from nagapasha.stages.stage03_targeting import run_targeting, _auto_target


def _make_param(name, location="query", param_type="free_text", value="test",
                do_not_fuzz=False):
    return ParameterModel(
        name=name,
        location=location,
        inferred_type=param_type,
        raw_value=value,
        is_fuzz_target=False,
        do_not_fuzz=do_not_fuzz,
    )


def _make_request(params=None):
    if params is None:
        params = [
            _make_param("id", "query", "int", "42"),
            _make_param("name", "query", "free_text", "john"),
            _make_param("Authorization", "header", "free_text", "Bearer xyz",
                        do_not_fuzz=True),
        ]
    return RequestModel(
        method="GET",
        url="https://example.com/api/item",
        base_url="https://example.com",
        headers={"Authorization": "Bearer xyz"},
        query_params={"id": "42", "name": "john"},
        parameters=params,
    )


class TestAutoTarget:
    def test_auto_target_fuzzes_non_auth(self):
        """Auto-target should fuzz all non-auth parameters."""
        req = _make_request()
        result = _auto_target(req)

        # id and name should be fuzz targets
        assert result.parameters[0].is_fuzz_target is True  # id
        assert result.parameters[1].is_fuzz_target is True  # name
        # Authorization should not be fuzzed (do_not_fuzz=True)
        assert result.parameters[2].is_fuzz_target is False  # Authorization

    def test_auto_target_clears_do_not_fuzz(self):
        """Auto-target should clear do_not_fuzz on selected params."""
        req = _make_request()
        result = _auto_target(req)

        assert result.parameters[0].do_not_fuzz is False
        assert result.parameters[1].do_not_fuzz is False


class TestRunTargeting:
    def test_empty_parameters(self):
        """No parameters should return model unchanged."""
        req = _make_request(params=[])
        result = run_targeting(req, auto=True)
        assert len(result.parameters) == 0

    def test_auto_mode(self):
        """Auto mode should fuzz eligible parameters."""
        req = _make_request()
        result = run_targeting(req, auto=True)

        count = sum(1 for p in result.parameters if p.is_fuzz_target)
        assert count == 2  # id and name

    def test_auto_mode_all(self):
        """'all' answer should fuzz all eligible."""
        # In auto mode, we bypass user prompt
        req = _make_request()
        result = run_targeting(req, auto=True)
        count = sum(1 for p in result.parameters if p.is_fuzz_target)
        assert count == 2
