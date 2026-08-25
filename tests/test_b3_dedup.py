"""B3 tests: Target deduplication module (stage13_target_dedup).

Verifies:
- normalize_path() strips trailing slash, lowercases
- deduplicate_endpoints() deduplicates by method+path
- Duplicate merging preserves parameters, risk_tags, body_schema, base_url
- Empty input returns empty result
- No duplicates returns original endpoints
"""

import pytest
from dataclasses import dataclass, field
from typing import Optional, Any, List

from nagapasha.stages.stage13_target_dedup import (
    DeduplicationResult,
    normalize_path,
    deduplicate_endpoints,
    merge_endpoint,
)
from nagapasha.models.request_model import ParameterModel


# ---------------------------------------------------------------------------
# Mock DiscoveredEndpoint for testing
# ---------------------------------------------------------------------------


@dataclass
class MockEndpoint:
    """Simplified DiscoveredEndpoint for testing deduplication."""

    method: str
    path_template: str
    parameters: List[ParameterModel] = field(default_factory=list)
    body_schema: Optional[dict[str, Any]] = None
    risk_tags: list[str] = field(default_factory=list)
    base_url: Optional[str] = None
    source: str = "test"

    def full_url(self) -> str:
        return f"{self.base_url or ''}/{self.path_template.lstrip('/')}"


# ---------------------------------------------------------------------------
# normalize_path
# ---------------------------------------------------------------------------


class TestNormalizePath:
    """B3: Verify normalize_path() logic."""

    def test_strips_trailing_slash(self):
        """B3: normalize_path() must strip trailing slash."""
        assert normalize_path("/users/") == "/users"

    def test_strips_multiple_trailing_slashes(self):
        """B3: normalize_path() must strip multiple trailing slashes."""
        assert normalize_path("/users///") == "/users"

    def test_preserves_root_slash(self):
        """B3: normalize_path() must preserve root slash."""
        assert normalize_path("/") == "/"

    def test_lowercases(self):
        """B3: normalize_path() must lowercase the path."""
        assert normalize_path("/Users") == "/users"

    def test_lowercases_with_trailing_slash(self):
        """B3: normalize_path() must lowercase and strip trailing slash."""
        assert normalize_path("/Users/") == "/users"

    def test_preserves_path_params(self):
        """B3: normalize_path() must preserve path parameters."""
        assert normalize_path("/users/{id}") == "/users/{id}"

    def test_lowercases_path_params(self):
        """B3: normalize_path() must lowercase path parameters."""
        assert normalize_path("/Users/{UserId}") == "/users/{userid}"


# ---------------------------------------------------------------------------
# deduplicate_endpoints
# ---------------------------------------------------------------------------


class TestDeduplicateEndpoints:
    """B3: Verify deduplicate_endpoints() logic."""

    def test_empty_input(self):
        """B3: Empty input must return empty result."""
        result = deduplicate_endpoints([])
        assert result.deduped_count == 0
        assert result.removed_count == 0
        assert result.endpoints == []

    def test_no_duplicates(self):
        """B3: No duplicates must return original endpoints."""
        endpoints = [
            MockEndpoint(method="GET", path_template="/users"),
            MockEndpoint(method="POST", path_template="/users"),
            MockEndpoint(method="GET", path_template="/posts"),
        ]
        result = deduplicate_endpoints(endpoints)
        assert result.deduped_count == 3
        assert result.removed_count == 0
        assert len(result.endpoints) == 3

    def test_deduplicates_same_method_path(self):
        """B3: Duplicate same method+path must be merged."""
        endpoints = [
            MockEndpoint(method="GET", path_template="/users"),
            MockEndpoint(method="GET", path_template="/users"),
            MockEndpoint(method="GET", path_template="/users"),
        ]
        result = deduplicate_endpoints(endpoints)
        assert result.deduped_count == 1
        assert result.removed_count == 2

    def test_deduplicates_case_insensitive(self):
        """B3: Duplicate case-insensitive path must be merged."""
        endpoints = [
            MockEndpoint(method="GET", path_template="/users"),
            MockEndpoint(method="GET", path_template="/Users"),
            MockEndpoint(method="GET", path_template="/USERS"),
        ]
        result = deduplicate_endpoints(endpoints)
        assert result.deduped_count == 1
        assert result.removed_count == 2

    def test_deduplicates_trailing_slash(self):
        """B3: Duplicate with/without trailing slash must be merged."""
        endpoints = [
            MockEndpoint(method="GET", path_template="/users"),
            MockEndpoint(method="GET", path_template="/users/"),
        ]
        result = deduplicate_endpoints(endpoints)
        assert result.deduped_count == 1
        assert result.removed_count == 1

    def test_different_methods_not_merged(self):
        """B3: Same path, different methods must NOT be merged."""
        endpoints = [
            MockEndpoint(method="GET", path_template="/users"),
            MockEndpoint(method="POST", path_template="/users"),
            MockEndpoint(method="DELETE", path_template="/users"),
        ]
        result = deduplicate_endpoints(endpoints)
        assert result.deduped_count == 3
        assert result.removed_count == 0

    def test_merge_parameters(self):
        """B3: Duplicate must merge parameters."""
        primary = MockEndpoint(
            method="GET",
            path_template="/users",
            parameters=[
                ParameterModel(name="limit", location="query", inferred_type="int", raw_value=""),
            ],
        )
        duplicate = MockEndpoint(
            method="GET",
            path_template="/users",
            parameters=[
                ParameterModel(name="offset", location="query", inferred_type="int", raw_value=""),
            ],
        )
        deduplicate_endpoints([primary, duplicate])
        param_names = {p.name for p in primary.parameters}
        assert param_names == {"limit", "offset"}

    def test_merge_parameters_same_name_location(self):
        """B3: Duplicate with same parameter name+location must NOT duplicate."""
        primary = MockEndpoint(
            method="GET",
            path_template="/users",
            parameters=[
                ParameterModel(name="limit", location="query", inferred_type="int", raw_value=""),
            ],
        )
        duplicate = MockEndpoint(
            method="GET",
            path_template="/users",
            parameters=[
                ParameterModel(name="limit", location="query", inferred_type="int", raw_value=""),
            ],
        )
        deduplicate_endpoints([primary, duplicate])
        limit_count = sum(1 for p in primary.parameters if p.name == "limit")
        assert limit_count == 1

    def test_merge_risk_tags(self):
        """B3: Duplicate must merge risk_tags."""
        primary = MockEndpoint(
            method="GET",
            path_template="/users",
            risk_tags=["auth"],
        )
        duplicate = MockEndpoint(
            method="GET",
            path_template="/users",
            risk_tags=["write"],
        )
        deduplicate_endpoints([primary, duplicate])
        assert "auth" in primary.risk_tags
        assert "write" in primary.risk_tags

    def test_merge_body_schema(self):
        """B3: Duplicate with None body_schema must take from duplicate."""
        primary = MockEndpoint(
            method="GET",
            path_template="/users",
            body_schema=None,
        )
        duplicate = MockEndpoint(
            method="GET",
            path_template="/users",
            body_schema={"type": "object"},
        )
        deduplicate_endpoints([primary, duplicate])
        assert primary.body_schema == {"type": "object"}

    def test_merge_base_url(self):
        """B3: Duplicate with None base_url must take from duplicate."""
        primary = MockEndpoint(
            method="GET",
            path_template="/users",
            base_url=None,
        )
        duplicate = MockEndpoint(
            method="GET",
            path_template="/users",
            base_url="https://api.example.com",
        )
        deduplicate_endpoints([primary, duplicate])
        assert primary.base_url == "https://api.example.com"

    def test_result_structure(self):
        """B3: Result must have all required fields."""
        result = DeduplicationResult()
        assert result.endpoints == []
        assert result.original_count == 0
        assert result.deduped_count == 0
        assert result.removed_count == 0
        assert result.warnings == []


# ---------------------------------------------------------------------------
# merge_endpoint
# ---------------------------------------------------------------------------


class TestMergeEndpoint:
    """B3: Verify merge_endpoint() logic."""

    def test_merge_parameters(self):
        """B3: merge_endpoint() must merge parameters."""
        primary = MockEndpoint(
            method="GET",
            path_template="/users",
            parameters=[
                ParameterModel(name="limit", location="query", inferred_type="int", raw_value=""),
            ],
        )
        duplicate = MockEndpoint(
            method="GET",
            path_template="/users",
            parameters=[
                ParameterModel(name="offset", location="query", inferred_type="int", raw_value=""),
            ],
        )
        merge_endpoint(primary, duplicate)
        param_names = {p.name for p in primary.parameters}
        assert param_names == {"limit", "offset"}

    def test_merge_risk_tags(self):
        """B3: merge_endpoint() must merge risk_tags."""
        primary = MockEndpoint(
            method="GET",
            path_template="/users",
            risk_tags=["auth"],
        )
        duplicate = MockEndpoint(
            method="GET",
            path_template="/users",
            risk_tags=["write"],
        )
        merge_endpoint(primary, duplicate)
        assert "auth" in primary.risk_tags
        assert "write" in primary.risk_tags

    def test_merge_body_schema(self):
        """B3: merge_endpoint() must merge body_schema."""
        primary = MockEndpoint(
            method="GET",
            path_template="/users",
            body_schema=None,
        )
        duplicate = MockEndpoint(
            method="GET",
            path_template="/users",
            body_schema={"type": "object"},
        )
        merge_endpoint(primary, duplicate)
        assert primary.body_schema == {"type": "object"}

    def test_merge_base_url(self):
        """B3: merge_endpoint() must merge base_url."""
        primary = MockEndpoint(
            method="GET",
            path_template="/users",
            base_url=None,
        )
        duplicate = MockEndpoint(
            method="GET",
            path_template="/users",
            base_url="https://api.example.com",
        )
        merge_endpoint(primary, duplicate)
        assert primary.base_url == "https://api.example.com"

    def test_no_duplicate_parameters(self):
        """B3: merge_endpoint() must not duplicate parameters."""
        primary = MockEndpoint(
            method="GET",
            path_template="/users",
            parameters=[
                ParameterModel(name="limit", location="query", inferred_type="int", raw_value=""),
            ],
        )
        duplicate = MockEndpoint(
            method="GET",
            path_template="/users",
            parameters=[
                ParameterModel(name="limit", location="query", inferred_type="int", raw_value=""),
            ],
        )
        merge_endpoint(primary, duplicate)
        limit_count = sum(1 for p in primary.parameters if p.name == "limit")
        assert limit_count == 1
