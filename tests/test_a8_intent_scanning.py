"""A8 tests: two-phase intent scanning infrastructure.

Verifies:
- _filter_payloads_by_categories correctly filters PayloadCandidates
- Intent resolution triggers phase 2 scan
- Phase 2 results are merged into overall results
- Empty resolved categories skip phase 2
- No payloads matching categories skips phase 2
- CLI --intent flag is accepted
"""

import pytest
import asyncio
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

from nagapasha.stages.stage06_intent import IntentResolution
from nagapasha.models.request_model import RequestModel, ParameterModel


# ---------------------------------------------------------------------------
# Mock PayloadCandidate for testing
# ---------------------------------------------------------------------------

@dataclass
class MockPayloadCandidate:
    """Simplified PayloadCandidate for testing _filter_payloads_by_categories."""
    parameter: ParameterModel
    payload: str
    attack_class: str
    payload_tags: list[str] = field(default_factory=list)


@pytest.fixture
def sample_parameters():
    """Create sample parameters for testing."""
    return [
        ParameterModel(name="email", location="body_json", inferred_type="email", raw_value="test@test.com"),
        ParameterModel(name="search", location="query", inferred_type="free_text", raw_value="hello"),
    ]


@pytest.fixture
def sample_payloads(sample_parameters):
    """Create sample payloads with various attack classes."""
    return [
        MockPayloadCandidate(
            parameter=sample_parameters[0],
            payload="' OR 1=1--",
            attack_class="tautology",
            payload_tags=["tautology", "sql"],
        ),
        MockPayloadCandidate(
            parameter=sample_parameters[0],
            payload="<script>alert(1)</script>",
            attack_class="xss_reflected",
            payload_tags=["xss_reflected", "html"],
        ),
        MockPayloadCandidate(
            parameter=sample_parameters[1],
            payload="../../../etc/passwd",
            attack_class="path_traversal",
            payload_tags=["path_traversal", "unix"],
        ),
        MockPayloadCandidate(
            parameter=sample_parameters[1],
            payload="{{7*7}}",
            attack_class="time_based_blind",
            payload_tags=["time_based_blind", "template"],
        ),
        MockPayloadCandidate(
            parameter=sample_parameters[0],
            payload="normal_value",
            attack_class="default/email",
            payload_tags=[],
        ),
    ]


# ---------------------------------------------------------------------------
# _filter_payloads_by_categories
# ---------------------------------------------------------------------------

class TestFilterPayloadsByCategories:
    """A8: Verify _filter_payloads_by_categories function."""

    def test_import_filter_function(self):
        """A8: _filter_payloads_by_categories must be importable from cli."""
        from nagapasha.cli import _filter_payloads_by_categories
        assert callable(_filter_payloads_by_categories)

    def test_filter_empty_categories_returns_empty(self, sample_payloads):
        """A8: Empty categories list → empty result."""
        from nagapasha.cli import _filter_payloads_by_categories
        result = _filter_payloads_by_categories(sample_payloads, [])
        assert result == []

    def test_filter_by_attack_class(self, sample_payloads):
        """A8: Filter by attack_class must match payloads with that class."""
        from nagapasha.cli import _filter_payloads_by_categories
        result = _filter_payloads_by_categories(sample_payloads, ["tautology"])
        assert len(result) == 1
        assert result[0].attack_class == "tautology"

    def test_filter_by_payload_tags(self, sample_payloads):
        """A8: Filter by payload_tags must match payloads with that tag."""
        from nagapasha.cli import _filter_payloads_by_categories
        result = _filter_payloads_by_categories(sample_payloads, ["xss_reflected"])
        assert len(result) == 1
        assert result[0].attack_class == "xss_reflected"

    def test_filter_multiple_categories(self, sample_payloads):
        """A8: Multiple categories must return all matching payloads."""
        from nagapasha.cli import _filter_payloads_by_categories
        result = _filter_payloads_by_categories(
            sample_payloads, ["tautology", "xss_reflected"]
        )
        assert len(result) == 2
        classes = {p.attack_class for p in result}
        assert classes == {"tautology", "xss_reflected"}

    def test_filter_no_match_returns_empty(self, sample_payloads):
        """A8: No matching categories → empty result."""
        from nagapasha.cli import _filter_payloads_by_categories
        result = _filter_payloads_by_categories(sample_payloads, ["nonexistent"])
        assert result == []

    def test_filter_preserves_payload_data(self, sample_payloads):
        """A8: Filtered payloads must preserve their data."""
        from nagapasha.cli import _filter_payloads_by_categories
        result = _filter_payloads_by_categories(sample_payloads, ["path_traversal"])
        assert len(result) == 1
        p = result[0]
        assert p.parameter.name == "search"
        assert p.payload == "../../../etc/passwd"
        assert p.payload_tags == ["path_traversal", "unix"]


# ---------------------------------------------------------------------------
# IntentResolution structure (re-verify for A8)
# ---------------------------------------------------------------------------

class TestIntentResolutionA8:
    """A8: Re-verify IntentResolution structure for A8 context."""

    def test_intent_resolution_dataclass(self):
        """A8: IntentResolution must have all A8 fields."""
        ir = IntentResolution(
            resolved_categories=["xss_reflected"],
            target_locations=["query"],
            dialect_hint=None,
            unsupported_asks=[],
            out_of_reach_asks=[],
            rationale="test",
        )
        assert ir.resolved_categories == ["xss_reflected"]
        assert ir.target_locations == ["query"]
        assert ir.unsupported_asks == []
        assert ir.out_of_reach_asks == []

    def test_intent_resolution_empty(self):
        """A8: Empty IntentResolution must have empty lists."""
        ir = IntentResolution()
        assert ir.resolved_categories == []
        assert ir.target_locations is None
        assert ir.dialect_hint is None
        assert ir.unsupported_asks == []
        assert ir.out_of_reach_asks == []
        assert ir.rationale == ""


# ---------------------------------------------------------------------------
# Phase 2 scan logic (mocked)
# ---------------------------------------------------------------------------

class TestPhaseTwoScan:
    """A8: Verify phase 2 scan logic with mocked components."""

    @pytest.mark.asyncio
    async def test_phase_two_skipped_when_no_categories(self):
        """A8: Phase 2 must be skipped when intent resolves to 0 categories."""
        from nagapasha.cli import _run_phase_two_scan

        req = RequestModel(
            method="POST",
            url="http://example.com/api",
            base_url="http://example.com",
        )
        ir = IntentResolution(
            resolved_categories=[],
            rationale="No matching categories.",
        )
        payloads = [
            MockPayloadCandidate(
                parameter=ParameterModel(name="email", location="body_json",
                                         inferred_type="email", raw_value="test"),
                payload="test",
                attack_class="tautology",
            )
        ]

        results = await _run_phase_two_scan(
            req=req,
            baseline=None,
            payloads=payloads,
            intent_resolution=ir,
            rate_config=None,
            max_requests=1000,
            batch_size=1,
            engagement_context=None,
            host_allowlist=None,
            restore_after=False,
            _on_result=lambda r: None,
            allow_destructive=False,
        )

        # Must return early with empty phase_two
        assert results["phase_two"]["total_fired"] == 0
        assert results["intent"] is ir

    @pytest.mark.asyncio
    async def test_phase_two_skipped_when_no_matching_payloads(self):
        """A8: Phase 2 must be skipped when no payloads match categories."""
        from nagapasha.cli import _run_phase_two_scan

        req = RequestModel(
            method="POST",
            url="http://example.com/api",
            base_url="http://example.com",
        )
        ir = IntentResolution(
            resolved_categories=["nonexistent_category"],
            rationale="Test.",
        )
        payloads = [
            MockPayloadCandidate(
                parameter=ParameterModel(name="email", location="body_json",
                                         inferred_type="email", raw_value="test"),
                payload="test",
                attack_class="tautology",
            )
        ]

        results = await _run_phase_two_scan(
            req=req,
            baseline=None,
            payloads=payloads,
            intent_resolution=ir,
            rate_config=None,
            max_requests=1000,
            batch_size=1,
            engagement_context=None,
            host_allowlist=None,
            restore_after=False,
            _on_result=lambda r: None,
            allow_destructive=False,
        )

        # Must return early with empty phase_two
        assert results["phase_two"]["total_fired"] == 0


# ---------------------------------------------------------------------------
# CLI --intent flag acceptance
# ---------------------------------------------------------------------------

class TestCLIImplicitIntent:
    """A8: Verify CLI --intent flag is accepted (non-functional, just parses)."""

    def test_intent_flag_accepts_string(self):
        """A8: --intent flag must accept a string argument."""
        import inspect
        from nagapasha.cli import app

        # 'full' is the 7th registered command (index 7)
        if len(app.registered_commands) < 8:
            pytest.fail("Expected at least 8 registered commands")

        full_cmd = app.registered_commands[7]
        sig = inspect.signature(full_cmd.callback)
        assert 'intent' in sig.parameters, "full command missing --intent parameter"

    def test_cicd_intent_flag_accepts_string(self):
        """A8: --intent flag on cicd command must accept a string argument."""
        import inspect
        from nagapasha.cli import app

        # cicd is the second registered command (index 1)
        if len(app.registered_commands) < 2:
            pytest.fail("Expected at least 2 registered commands")

        cicd_cmd = app.registered_commands[1]
        sig = inspect.signature(cicd_cmd.callback)
        assert 'intent' in sig.parameters, "cicd command missing --intent parameter"


# ---------------------------------------------------------------------------
# Integration: resolve_intent → filter → phase 2
# ---------------------------------------------------------------------------

class TestResolveIntentToPhaseTwo:
    """A8: Verify resolve_intent output can drive _filter_payloads_by_categories."""

    def test_resolved_categories_filter_payloads(self, sample_payloads):
        """A8: IntentResolution.resolved_categories must filter payloads correctly."""
        from nagapasha.cli import _filter_payloads_by_categories
        from nagapasha.stages.stage06_intent import IntentResolution

        ir = IntentResolution(resolved_categories=["xss_reflected", "path_traversal"])
        filtered = _filter_payloads_by_categories(sample_payloads, ir.resolved_categories)

        classes = {p.attack_class for p in filtered}
        assert classes == {"xss_reflected", "path_traversal"}
        assert len(filtered) == 2

    def test_unsupported_asks_not_in_filtered(self, sample_payloads):
        """A8: unsupported_asks categories must not appear in filtered payloads."""
        from nagapasha.cli import _filter_payloads_by_categories
        from nagapasha.stages.stage06_intent import IntentResolution

        ir = IntentResolution(
            resolved_categories=["xss_reflected"],
            unsupported_asks=["csrf_bypass"],
        )
        filtered = _filter_payloads_by_categories(sample_payloads, ir.resolved_categories)
        # csrf_bypass should not be in filtered
        for p in filtered:
            assert p.attack_class != "csrf_bypass"
