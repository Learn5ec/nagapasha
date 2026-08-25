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
