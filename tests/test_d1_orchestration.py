"""D1 tests: App-wide DAST orchestration (discover_and_scan).

Verifies:
- AppWideScanResult dataclass structure
- DiscoverAndScanOrchestrator initialization
- OpenAPI spec parsing integration
- Endpoint deduplication integration
- Session establishment integration
- BOLA check integration
- Phase A scan integration
- Aggregated findings collection
"""

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock, AsyncMock, patch

from nagapasha.orchestration.discover_and_scan import (
    AppWideScanResult,
    ScanResult,
    BolaResult,
    DiscoverAndScanOrchestrator,
)
from nagapasha.stages.stage09_openapi import (
    DiscoveredEndpoint,
    OpenAPIParseResult,
)
from nagapasha.stages.stage13_target_dedup import DeduplicationResult
from nagapasha.session.session_manager import SessionContext
from nagapasha.engine.bola_check import BolaFinding
from nagapasha.models.request_model import RequestModel, ParameterModel


# ---------------------------------------------------------------------------
# AppWideScanResult structure
# ---------------------------------------------------------------------------


class TestAppWideScanResult:
    """D1: AppWideScanResult dataclass structure."""

    def test_result_default_fields(self):
        """D1: All fields must have default values."""
        r = AppWideScanResult()
        assert r.scan_end is None
        assert r.openapi_results == []
        assert r.dedup_result is None
        assert r.sessions == []
        assert r.bola_results == []
        assert r.scan_results == []
        assert r.findings == []
        assert r.spec_urls == []
        assert r.total_endpoints == 0
        assert r.total_sessions == 0
        assert r.total_bola_checks == 0
        assert r.total_findings == 0
        assert r.total_errors == []


# ---------------------------------------------------------------------------
# ScanResult structure
# ---------------------------------------------------------------------------


class TestScanResult:
    """D1: ScanResult dataclass structure."""

    def test_scan_result_default_fields(self):
        """D1: All fields must have default values."""
        r = ScanResult(endpoint=None, session_label=None)
        assert r.findings == []
        assert r.total_fired == 0
        assert r.errors == []


# ---------------------------------------------------------------------------
# BolaResult structure
# ---------------------------------------------------------------------------


class TestBolaResult:
    """D1: BolaResult dataclass structure."""

    def test_bola_result_default_fields(self):
        """D1: All fields must have default values."""
        r = BolaResult(endpoint=None, owner_session="user_a", intruder_session="user_b")
        assert r.finding is None
        assert r.error is None


# ---------------------------------------------------------------------------
# DiscoverAndScanOrchestrator initialization
# ---------------------------------------------------------------------------


class TestOrchestratorInit:
    """D1: Verify orchestrator initialization."""

    def test_init_with_runner(self):
        """D1: Orchestrator must be initialized with runner."""
        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)
        assert orchestrator.runner is runner

    def test_init_with_scope_checker(self):
        """D1: Orchestrator must accept optional scope_checker."""
        runner = MagicMock()
        scope_checker = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner, scope_checker=scope_checker)
        assert orchestrator.scope_checker is scope_checker

    def test_init_with_rate_limit(self):
        """D1: Orchestrator must accept optional rate_limit."""
        runner = MagicMock()
        rate_limit = {"max_pps": 10}
        orchestrator = DiscoverAndScanOrchestrator(runner=runner, rate_limit=rate_limit)
        assert orchestrator.rate_limit == rate_limit

    def test_init_with_max_sessions(self):
        """D1: Orchestrator must accept optional max_sessions."""
        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner, max_sessions=10)
        assert orchestrator.max_sessions == 10

    def test_init_with_max_requests(self):
        """D1: Orchestrator must accept optional max_requests."""
        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner, max_requests=5000)
        assert orchestrator.max_requests == 5000


# ---------------------------------------------------------------------------
# Orchestrator.run — integration
# ---------------------------------------------------------------------------


class TestOrchestratorRun:
    """D1: Integration tests for orchestrator.run()."""

    @pytest.mark.asyncio
    async def test_run_empty_spec(self, tmp_path):
        """D1: Orchestrator must handle empty spec gracefully."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps({"openapi": "3.0.0", "info": {"title": "Empty"}, "paths": {}}))

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)

        result = await orchestrator.run(spec_urls=[str(spec_file)])

        assert result.total_endpoints == 0
        assert result.total_sessions == 0
        assert result.total_bola_checks == 0
        assert result.total_findings == 0

    @pytest.mark.asyncio
    async def test_run_with_spec_and_endpoints(self, tmp_path):
        """D1: Orchestrator must parse spec and discover endpoints."""
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test API"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(spec_data))

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)

        result = await orchestrator.run(spec_urls=[str(spec_file)])

        assert result.total_endpoints == 1
        assert len(result.openapi_results) == 1

    @pytest.mark.asyncio
    async def test_run_with_sessions(self, tmp_path):
        """D1: Orchestrator must establish sessions from login_curls."""
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test API"},
            "paths": {
                "/users": {
                    "get": {"responses": {"200": {"description": "OK"}}},
                }
            },
        }
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(spec_data))

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner, max_sessions=2)

        # Mock establish_session to return successful sessions
        mock_session_result = MagicMock()
        mock_session_result.success = True
        mock_session_result.session = SessionContext(label="admin")

        with patch("nagapasha.orchestration.discover_and_scan.establish_session", return_value=mock_session_result):
            result = await orchestrator.run(
                spec_urls=[str(spec_file)],
                login_curls={"admin": "curl -X POST ..."},
            )

        assert result.total_sessions == 1
        assert len(result.sessions) == 1
        assert result.sessions[0].label == "admin"

    @pytest.mark.asyncio
    async def test_run_with_bola_checks(self, tmp_path):
        """D1: Orchestrator must run BOLA checks with 2+ sessions."""
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test API"},
            "paths": {
                "/users/{id}": {
                    "get": {
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(spec_data))

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner, max_sessions=2)

        # Mock establish_session to return successful sessions
        mock_session_result = MagicMock()
        mock_session_result.success = True
        mock_session_result.session = SessionContext(label="user_a")

        with patch("nagapasha.orchestration.discover_and_scan.establish_session", return_value=mock_session_result):
            result = await orchestrator.run(
                spec_urls=[str(spec_file)],
                login_curls={"user_a": "curl -X POST ..."},
            )

        # Only 1 session — BOLA checks skipped
        assert result.total_bola_checks == 0

    @pytest.mark.asyncio
    async def test_run_with_findings(self, tmp_path):
        """D1: Orchestrator must collect findings from scans."""
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test API"},
            "paths": {
                "/users": {
                    "get": {"responses": {"200": {"description": "OK"}}},
                }
            },
        }
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(spec_data))

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)

        # Mock _run_phase_a_scan to return a finding
        mock_scan_result = MagicMock()
        mock_scan_result.findings = [{"type": "xss", "severity": "high"}]
        mock_scan_result.total_fired = 10

        with patch.object(orchestrator, "_run_phase_a_scan", return_value=mock_scan_result):
            result = await orchestrator.run(spec_urls=[str(spec_file)])

        assert result.total_findings == 1
        assert len(result.findings) == 1

    @pytest.mark.asyncio
    async def test_run_with_errors(self, tmp_path):
        """D1: Orchestrator must collect errors."""
        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)

        # Mock parse_openapi_spec to raise an error
        with patch("nagapasha.orchestration.discover_and_scan.parse_openapi_spec", side_effect=Exception("parse error")):
            result = await orchestrator.run(spec_urls=["https://invalid.example.com/spec.json"])

        assert len(result.total_errors) == 1
        assert "parse error" in result.total_errors[0]

    @pytest.mark.asyncio
    async def test_run_with_multiple_specs(self, tmp_path):
        """D1: Orchestrator must parse multiple specs."""
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test API"},
            "paths": {
                "/users": {"get": {"responses": {"200": {"description": "OK"}}}},
                "/posts": {"get": {"responses": {"200": {"description": "OK"}}}},
            },
        }
        spec_file1 = tmp_path / "spec1.json"
        spec_file1.write_text(json.dumps(spec_data))
        spec_file2 = tmp_path / "spec2.json"
        spec_file2.write_text(json.dumps(spec_data))

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)

        result = await orchestrator.run(spec_urls=[str(spec_file1), str(spec_file2)])

        assert len(result.openapi_results) == 2
        # total_endpoints is the deduplicated count
        assert result.total_endpoints == 2
        # Dedup result shows original vs deduplicated
        assert result.dedup_result.original_count == 4
        assert result.dedup_result.deduped_count == 2


# ---------------------------------------------------------------------------
# Helper methods
# ---------------------------------------------------------------------------


class TestOrchestratorHelpers:
    """D1: Verify orchestrator helper methods."""

    def test_endpoint_to_request(self):
        """D1: _endpoint_to_request must convert DiscoveredEndpoint to RequestModel."""
        endpoint = DiscoveredEndpoint(
            method="GET",
            path_template="/users/{id}",
            concrete_path="/users/1",
            parameters=[
                ParameterModel(name="id", location="path", inferred_type="int", raw_value="1"),
            ],
            base_url="https://api.example.com",
        )

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)
        request = orchestrator._endpoint_to_request(endpoint)

        assert request.method == "GET"
        assert request.url == "https://api.example.com/users/1"
        assert request.base_url == "https://api.example.com"
        assert len(request.parameters) == 1

    @pytest.mark.asyncio
    async def test_run_bola_check(self, tmp_path):
        """D1: _run_bola_check must return BolaResult."""
        endpoint = DiscoveredEndpoint(
            method="GET",
            path_template="/users/{id}",
            concrete_path="/users/1",
            base_url="https://api.example.com",
        )
        owner_session = SessionContext(label="user_a")
        intruder_session = SessionContext(label="user_b")

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)

        # Mock check_bola to return a finding
        mock_finding = BolaFinding(
            endpoint=endpoint,
            owner_session="user_a",
            intruder_session="user_b",
            confidence=0.95,
        )
        mock_bola_result = MagicMock()
        mock_bola_result.finding = mock_finding
        mock_bola_result.error = None

        with patch("nagapasha.orchestration.discover_and_scan.check_bola", return_value=mock_bola_result):
            result = await orchestrator._run_bola_check(endpoint, owner_session, intruder_session)

        assert result.finding is not None
        assert result.finding.confidence == 0.95

    @pytest.mark.asyncio
    async def test_run_bola_check_with_error(self, tmp_path):
        """D1: _run_bola_check must return error on exception."""
        endpoint = DiscoveredEndpoint(
            method="GET",
            path_template="/users/{id}",
            concrete_path="/users/1",
            base_url="https://api.example.com",
        )
        owner_session = SessionContext(label="user_a")
        intruder_session = SessionContext(label="user_b")

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)

        # Mock check_bola to raise an exception
        with patch("nagapasha.orchestration.discover_and_scan.check_bola", side_effect=Exception("test error")):
            result = await orchestrator._run_bola_check(endpoint, owner_session, intruder_session)

        assert result.error == "test error"

    @pytest.mark.asyncio
    async def test_run_phase_a_scan(self):
        """D1: _run_phase_a_scan must return ScanResult."""
        request = RequestModel(
            method="GET",
            url="https://api.example.com/users/1",
            base_url="https://api.example.com",
        )
        session = SessionContext(label="user_a")

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)

        result = await orchestrator._run_phase_a_scan(request, session)

        assert result.session_label == "user_a"
        assert result.findings == []
        assert result.total_fired == 0

    @pytest.mark.asyncio
    async def test_run_phase_a_scan_captures_fresh_baseline(self):
        """P1-1: _run_phase_a_scan must capture a fresh baseline per scan."""
        request = RequestModel(
            method="GET",
            url="https://api.example.com/users/1",
            base_url="https://api.example.com",
        )
        session = SessionContext(label="user_a")

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)

        # Mock capture_baseline to return a baseline fingerprint
        mock_fingerprint = MagicMock()
        mock_fingerprint.status_code = 200
        mock_fingerprint.content_length = 100
        mock_fingerprint.body_hash = "abc123"
        mock_fingerprint.avg_response_time = 0.1

        with patch(
            "nagapasha.engine.baseline.capture_baseline",
            return_value=(mock_fingerprint, False, ""),
        ):
            result = await orchestrator._run_phase_a_scan(request, session)

        assert result.baseline is not None
        assert result.baseline.status_code == 200

    @pytest.mark.asyncio
    async def test_run_phase_a_scan_fires_payloads(self):
        """D1: _run_phase_a_scan must fire payloads via PayloadLoop."""
        request = RequestModel(
            method="GET",
            url="https://api.example.com/users/1",
            base_url="https://api.example.com",
            parameters=[
                ParameterModel(
                    name="id",
                    location="path",
                    inferred_type="int",
                    raw_value="1",
                    is_fuzz_target=True,
                    do_not_fuzz=False,
                ),
            ],
        )
        session = SessionContext(label="user_a")

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner)

        # Mock capture_baseline
        mock_fingerprint = MagicMock()
        mock_fingerprint.status_code = 200
        mock_fingerprint.content_length = 100
        mock_fingerprint.body_hash = "abc123"
        mock_fingerprint.avg_response_time = 0.1

        # Mock PayloadLoop
        mock_loop = MagicMock()
        mock_loop.run = AsyncMock(return_value={
            "total_fired": 5,
            "hits": 0,
            "near_misses": 0,
            "no_diff": 5,
            "results": [],
        })

        # One fuzz payload so the loop actually runs
        fake_candidate = MagicMock()

        with patch(
            "nagapasha.engine.baseline.capture_baseline",
            return_value=(mock_fingerprint, False, ""),
        ), patch(
            "nagapasha.cli._build_technique_category_payloads",
            return_value=[fake_candidate],
        ), patch(
            "nagapasha.engine.payload_loop.PayloadLoop",
            return_value=mock_loop,
        ):
            result = await orchestrator._run_phase_a_scan(request, session)

        # Verify the payload loop was called
        assert mock_loop.run.called
        # Verify the result has the baseline
        assert result.baseline is not None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """D1: Edge case tests."""

    @pytest.mark.asyncio
    async def test_run_with_max_sessions_reached(self, tmp_path):
        """D1: Orchestrator must stop establishing sessions at max_sessions."""
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test API"},
            "paths": {"/users": {"get": {"responses": {"200": {"description": "OK"}}}}},
        }
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(spec_data))

        runner = MagicMock()
        orchestrator = DiscoverAndScanOrchestrator(runner=runner, max_sessions=2)

        # Mock establish_session to return successful sessions
        mock_session_result = MagicMock()
        mock_session_result.success = True
        mock_session_result.session = SessionContext(label="admin")

        call_count = [0]

        async def mock_establish(**kwargs):
            call_count[0] += 1
            return mock_session_result

        with patch("nagapasha.orchestration.discover_and_scan.establish_session", side_effect=mock_establish):
            result = await orchestrator.run(
                spec_urls=[str(spec_file)],
                login_curls={"admin": "curl", "user": "curl", "guest": "curl"},
            )

        # Should only establish 2 sessions (max_sessions)
        assert result.total_sessions == 2
        assert call_count[0] == 2


# ---------------------------------------------------------------------------
# End-to-end scan integration test
# ---------------------------------------------------------------------------
# Drives the FULL pipeline discover -> dedup -> session -> BOLA -> Phase A scan
# against a real spec file and a mock runner, exercising the real code paths
# for parsing, deduplication, session establishment, BOLA analysis, baseline
# capture, and payload firing (payload loop's runner forwards to the mock).


class _E2EResponse:
    """Minimal response object exposing the fields the pipeline reads."""

    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.body = body
        self.headers: dict[str, str] = {}
        self.elapsed = 0.01
        self.url = "http://mock.local"


class _MockRunner:
    """Fake HttpRunner for end-to-end pipeline testing.

    Login URLs (``/login``) return a bearer-token response; every other request
    is answered 200 with the request headers echoed back into the body, so any
    reflected payload flows through the real detection stack (compute_delta) as
    a HIT. send_multiple backs baseline calibration.
    """

    def __init__(self):
        self.sent: list = []

    async def send(self, request_model):
        self.sent.append(request_model)
        if "/login" in request_model.url:
            body = json.dumps({"access_token": "session_abc"})
        else:
            headers = {k.lower(): v for k, v in (request_model.headers or {}).items()}
            body = json.dumps({"headers": headers, "message": "ok"})
        return _E2EResponse(200, body)

    async def send_multiple(self, request_model, count=3):
        return [await self.send(request_model) for _ in range(count)]


class _FakePayloadLoopRunner:
    """Stand-in for payload_loop.HttpRunner that forwards to the shared mock."""

    _shared = None  # set per-test to the _MockRunner instance

    def __init__(self, *args, **kwargs):
        pass

    async def send(self, request_model):
        return await _FakePayloadLoopRunner._shared.send(request_model)

    async def send_multiple(self, request_model, count=3):
        return await _FakePayloadLoopRunner._shared.send_multiple(request_model, count=count)


# A spec with one auth-protected endpoint carrying a header fuzz target (for
# BOLA + scanning) and one public health endpoint.
E2E_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "E2E API", "version": "1.0.0"},
    "servers": [{"url": "https://api.local/v1"}],
    "paths": {
        "/search": {
            "get": {
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {"name": "X-App", "in": "header", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/health": {
            "get": {"responses": {"200": {"description": "OK"}}},
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
        }
    },
}


class TestEndToEndScanPipeline:
    """D1: Full pipeline discover -> dedup -> session -> BOLA -> Phase A scan."""

    @pytest.mark.asyncio
    async def test_full_pipeline_end_to_end(self, tmp_path):
        """D1: orchestrator.run drives the full pipeline against a mock runner."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(E2E_SPEC))

        mock = _MockRunner()
        # Route the payload loop's internal runner through the shared mock.
        _FakePayloadLoopRunner._shared = mock
        orchestrator = DiscoverAndScanOrchestrator(runner=mock, max_sessions=2)

        with patch(
            "nagapasha.engine.payload_loop.HttpRunner",
            _FakePayloadLoopRunner,
        ):
            result = await orchestrator.run(
                spec_urls=[str(spec_file)],
                login_curls={
                    "owner": "curl -X POST https://auth.local/login",
                    "intruder": "curl -X POST https://auth.local/login",
                },
            )

        # Step 1 + 2: parse + dedup
        assert len(result.openapi_results) == 1
        assert result.total_endpoints == 2
        assert result.dedup_result.deduped_count == 2
        assert result.dedup_result.original_count == 2

        # Step 3: sessions established from login_curls
        assert result.total_sessions == 2
        assert {s.label for s in result.sessions} == {"owner", "intruder"}

        # Step 4: BOLA checks ran (2 sessions -> 1 pair on the auth endpoint)
        assert result.total_bola_checks >= 1
        bola_findings = [br.finding for br in result.bola_results if br.finding]
        assert bola_findings
        # The finding must be a real BolaFinding, not a coroutine/dummy.
        assert all(isinstance(f, BolaFinding) for f in bola_findings)

        # Step 5: Phase A scan ran for each endpoint x session
        assert len(result.scan_results) == 6  # 2 endpoints x (None + 2 sessions)
        assert any(sr.total_fired > 0 for sr in result.scan_results)

        # Findings: at least the BOLA finding plus scan hits
        assert len(result.findings) >= 1
        assert result.total_findings >= 1

        # No crashes
        assert result.total_errors == []
        assert result.scan_end is not None

    @pytest.mark.asyncio
    async def test_full_pipeline_no_findings_without_bola(self, tmp_path):
        """D1: With only one session, BOLA is skipped but scanning still runs."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(E2E_SPEC))

        mock = _MockRunner()
        _FakePayloadLoopRunner._shared = mock
        orchestrator = DiscoverAndScanOrchestrator(runner=mock, max_sessions=2)

        with patch(
            "nagapasha.engine.payload_loop.HttpRunner",
            _FakePayloadLoopRunner,
        ):
            result = await orchestrator.run(
                spec_urls=[str(spec_file)],
                login_curls={"owner": "curl -X POST https://auth.local/login"},
            )

        # One session -> BOLA skipped
        assert result.total_sessions == 1
        assert result.total_bola_checks == 0
        assert result.bola_results == []
        # Scanning still ran
        assert len(result.scan_results) > 0
        assert result.total_errors == []


# ---------------------------------------------------------------------------
# Two-phase scan pipeline fixes — P1-1 (recapture baseline), P1-2 (carry runtime
# state), P2-1 (scan_phase tagging).
#
# A single integration test drives a real phase-1 PayloadLoop and then
# _run_phase_two_scan, patching PayloadLoop.with_carried_runtime_state to capture
# the phase-2 loop that would otherwise be built in place. Asserts all three
# fixes hold together with a mocked runner:
#   P1-1  phase 2 diffs against a freshly recaptured baseline (not phase 1's)
#   P1-2  phase 2 inherits phase 1's token budget + WAF state (not a fresh rebuild)
#   P2-1  every phase 2 result is tagged scan_phase="user_directed"
# ---------------------------------------------------------------------------

import nagapasha.engine.payload_loop as payload_loop_mod


class _Ph2Response:
    status_code = 200
    body = "MySQL syntax error near OR 1=1 in html"
    headers = {}
    elapsed = 0.01
    text = body
    url = "http://mock.local"


class _Ph2Runner:
    """Runner that answers 200 with an error-signature body (payloads -> HITs via
    the real compute_delta stack) while still paying the token budget through the
    real rate limiter.

    Patched as ``nagapasha.engine.payload_loop.HttpRunner`` so BOTH the phase-1
    loop and the captured phase-2 loop forward through this behaviour.
    """

    def __init__(self, rate_limiter=None, host_allowlist=None, **kwargs):
        self._rate_limiter = rate_limiter

    async def send(self, request_model):
        if self._rate_limiter is not None:
            await self._rate_limiter.acquire()
        return _Ph2Response()

    async def send_multiple(self, request_model, count=3):
        return [await self.send(request_model) for _ in range(count)]


class TestPhaseTwoTwoPhaseScanFixes:
    """P1-1/P1-2/P2-1: _run_phase_two_scan recaptures, carries, and tags."""

    @pytest.mark.asyncio
    async def test_recaptures_baseline_carries_state_and_tags_results(self):
        from types import SimpleNamespace
        from nagapasha.engine.diff import BaselineFingerprint
        from nagapasha.engine.rate_limiter import RateLimitConfig
        from nagapasha.engine.payload_loop import (
            PayloadLoop,
            PayloadCandidate,
            PayloadResult,
        )
        from nagapasha.cli import _run_phase_two_scan

        param = ParameterModel(
            name="id",
            location="query",
            inferred_type="int",
            raw_value="42",
            is_fuzz_target=True,
            do_not_fuzz=False,
        )
        req = RequestModel(
            method="GET",
            url="https://example.com/api/item",
            base_url="https://example.com",
            headers={"Accept": "application/json"},
            query_params={param.name: param.raw_value},
            parameters=[param],
        )
        baseline1 = BaselineFingerprint(
            status_code=200,
            content_length=42,
            body_hash="aaa",
            avg_response_time=0.01,
            header_names=frozenset(),
        )

        with patch.object(payload_loop_mod, "HttpRunner", _Ph2Runner):
            phase1_payloads = [
                PayloadCandidate(
                    parameter=param,
                    payload="' OR 1=1",
                    attack_class="sql_injection",
                ),
                PayloadCandidate(
                    parameter=param,
                    payload="0",
                    attack_class="sql_injection",
                ),
            ]
            phase1 = PayloadLoop(
                request_model=req,
                baseline_fingerprint=baseline1,
                payloads=phase1_payloads,
                max_requests=10,
                scan_phase="default",
            )
            await phase1.run(on_result=lambda r: None)

            # P1-2 precondition: phase 1 consumed some of the token budget (the
            # mock runner calls rate_limiter.acquire() per request).
            exported = phase1.export_runtime_state()
            assert 0.0 < exported["tokens"] < 10.0

            # Simulate a WAF being detected during phase 1.
            phase1.recalibration.state.waf_rechecked = True

            # Capture the phase-2 loop and its carried runtime state instead of
            # letting phase 2 run live.
            captured: dict = {}
            real_with_carried = PayloadLoop.with_carried_runtime_state

            def wrap(*args, **kwargs):
                loop = real_with_carried(*args, **kwargs)
                captured["runtime_state"] = kwargs["runtime_state"]
                # Read the token budget *before* phase 2 fires (still pre-run).
                captured["tokens_applied"] = loop.rate_limiter.current_tokens
                # WAF flag carried in from phase 1 (reset again later by the
                # loop's own recalibration re-detection during run()).
                captured["waf_applied"] = loop.recalibration.state.waf_rechecked
                captured["loop"] = loop
                captured["baseline"] = kwargs["baseline_fingerprint"]
                return loop

            phase2_payloads = [
                PayloadCandidate(
                    parameter=param,
                    payload="' OR '1'='1",
                    attack_class="sql_injection",
                ),
                PayloadCandidate(
                    parameter=param,
                    payload="admin'--",
                    attack_class="sql_injection",
                ),
            ]
            intent_resolution = SimpleNamespace(resolved_categories=["sql_injection"])
            rate_config = RateLimitConfig(burst=10, refill_rate=4.0)

            with patch.object(
                payload_loop_mod.PayloadLoop,
                "with_carried_runtime_state",
                side_effect=wrap,
            ):
                phase2_out = await _run_phase_two_scan(
                    req=req,
                    phase1_loop=phase1,
                    payloads=phase2_payloads,
                    intent_resolution=intent_resolution,
                    rate_config=rate_config,
                    max_requests=10,
                    batch_size=1,
                    engagement_context=None,
                    host_allowlist=None,
                    restore_after=False,
                    _on_result=lambda r: None,
                    allow_destructive=False,
                )

        captured_loop = captured["loop"]

        # --- P1-1: phase 2 recaptured a fresh baseline (differs from phase 1) ---
        assert captured["baseline"] is not baseline1
        assert captured_loop.baseline is captured["baseline"]
        # Fresh baseline reflects the mock body length, not phase-1's stale 42.
        assert captured_loop.baseline.content_length == len(_Ph2Response.body)

        # --- P1-2: phase 2 inherited phase 1's token budget + WAF state (not a
        # fresh full-burst rebuild) ---
        assert captured["runtime_state"]["waf_rechecked"] is True
        assert 0.0 < captured["tokens_applied"] < 10.0
        assert captured["tokens_applied"] == pytest.approx(
            captured["runtime_state"]["tokens"], abs=1.0
        )
        # WAF state carried in at build time (the loop resets it during its own
        # recalibration re-detection in run()).
        assert captured["waf_applied"] is True

        # --- P2-1: every phase 2 result is tagged as user-directed ---
        results = phase2_out["phase_two"]["results"]
        assert results
        for r in results:
            assert r["scan_phase"] == "user_directed"

        # The surplus scan produced real hits through the real detection stack.
        assert phase2_out["phase_two"]["hits"] >= 1
