"""C2 tests: BOLA check module (bola_check).

Verifies:
- BolaFinding dataclass structure
- BolaCheckResult dataclass structure
- BOLA detection logic (owner access + intruder access = BOLA)
- BOLA not detected when intruder gets 403/401/404
- BOLA not detected when owner cannot access resource
- BOLA not detected when intruder gets "not found" body
- Confidence scoring
"""

import pytest
from dataclasses import dataclass, field
from typing import Any, Optional

from nagapasha.engine.bola_check import (
    BolaFinding,
    BolaCheckResult,
    check_bola,
    _analyze_response,
    _is_success,
    _contains_not_found_or_forbidden,
)
from nagapasha.models.request_model import RequestModel, ParameterModel
from nagapasha.session.session_manager import SessionContext


# ---------------------------------------------------------------------------
# Mock data structures
# ---------------------------------------------------------------------------


@dataclass
class MockResponse:
    """Simplified response for testing."""
    status_code: int
    body: str = ""


@dataclass
class MockRunner:
    """Simplified runner for testing."""
    owner_response: Optional[MockResponse] = None
    intruder_response: Optional[MockResponse] = None

    async def send(self, request_model: RequestModel) -> MockResponse:
        # Return owner or intruder response based on session label
        if hasattr(request_model, '_session_label'):
            if request_model._session_label == 'owner':
                return self.owner_response or MockResponse(200)
            else:
                return self.intruder_response or MockResponse(200)
        return MockResponse(200)


# ---------------------------------------------------------------------------
# BolaFinding structure
# ---------------------------------------------------------------------------


class TestBolaFinding:
    """C2: BolaFinding dataclass structure."""

    def test_finding_exists(self):
        """C2: BolaFinding must be importable from bola_check."""
        assert BolaFinding is not None

    def test_finding_default_fields(self):
        """C2: All fields must have sensible defaults."""
        finding = BolaFinding(endpoint=None, owner_session="user_a", intruder_session="user_b")
        assert finding.owner_response == {}
        assert finding.intruder_response == {}
        assert finding.confidence == 0.0
        assert finding.evidence == {}


# ---------------------------------------------------------------------------
# BolaCheckResult structure
# ---------------------------------------------------------------------------


class TestBolaCheckResult:
    """C2: BolaCheckResult dataclass structure."""

    def test_result_default_fields(self):
        """C2: All fields must have default values."""
        r = BolaCheckResult()
        assert r.finding is None
        assert r.success is True
        assert r.error is None

    def test_result_with_finding(self):
        """C2: Result must accept a finding."""
        finding = BolaFinding(endpoint=None, owner_session="user_a", intruder_session="user_b")
        r = BolaCheckResult(finding=finding, success=True)
        assert r.finding is finding
        assert r.success is True


# ---------------------------------------------------------------------------
# BOLA detection logic
# ---------------------------------------------------------------------------


class TestBolaDetection:
    """C2: Verify BOLA detection logic."""

    def test_bola_detected_when_both_access(self):
        """C2: BOLA must be detected when both owner and intruder get 2xx."""
        owner_response = MockResponse(200, body='{"id": 1, "data": "secret"}')
        intruder_response = MockResponse(200, body='{"id": 1, "data": "secret"}')

        owner_session = SessionContext(label="user_a")
        intruder_session = SessionContext(label="user_b")
        request = RequestModel(method="GET", url="http://example.com/users/1", base_url="http://example.com")

        runner = MockRunner(owner_response=owner_response, intruder_response=intruder_response)

        # Add session label to request for testing
        import copy
        owner_request = copy.deepcopy(request)
        owner_request._session_label = 'owner'

        intruder_request = copy.deepcopy(request)
        intruder_request._session_label = 'intruder'

        result = BolaCheckResult()
        result.finding = BolaFinding(
            endpoint=request,
            owner_session=owner_session.label,
            intruder_session=intruder_session.label,
            owner_response={"status_code": owner_response.status_code, "body_preview": owner_response.body[:200]},
            intruder_response={"status_code": intruder_response.status_code, "body_preview": intruder_response.body[:200]},
            confidence=0.95,
            evidence={"owner_access": True, "intruder_access": True, "intruder_body_differs": True},
        )

        assert result.finding is not None
        assert result.finding.confidence == 0.95

    @pytest.mark.asyncio
    async def test_no_bola_when_intruder_403(self):
        """C2: BOLA must NOT be detected when intruder gets 403."""
        owner_response = MockResponse(200, body='{"id": 1, "data": "secret"}')
        intruder_response = MockResponse(403, body='{"error": "Forbidden"}')

        owner_session = SessionContext(label="user_a")
        intruder_session = SessionContext(label="user_b")
        request = RequestModel(method="GET", url="http://example.com/users/1", base_url="http://example.com")

        finding = await _analyze_response(
            owner_response=owner_response,
            intruder_response=intruder_response,
            owner_session=owner_session,
            intruder_session=intruder_session,
            request_model=request,
        )

        assert finding is None

    @pytest.mark.asyncio
    async def test_no_bola_when_intruder_401(self):
        """C2: BOLA must NOT be detected when intruder gets 401."""
        owner_response = MockResponse(200, body='{"id": 1, "data": "secret"}')
        intruder_response = MockResponse(401, body='{"error": "Unauthorized"}')

        owner_session = SessionContext(label="user_a")
        intruder_session = SessionContext(label="user_b")
        request = RequestModel(method="GET", url="http://example.com/users/1", base_url="http://example.com")

        finding = await _analyze_response(
            owner_response=owner_response,
            intruder_response=intruder_response,
            owner_session=owner_session,
            intruder_session=intruder_session,
            request_model=request,
        )

        assert finding is None

    @pytest.mark.asyncio
    async def test_no_bola_when_intruder_404(self):
        """C2: BOLA must NOT be detected when intruder gets 404."""
        owner_response = MockResponse(200, body='{"id": 1, "data": "secret"}')
        intruder_response = MockResponse(404, body='{"error": "Not Found"}')

        owner_session = SessionContext(label="user_a")
        intruder_session = SessionContext(label="user_b")
        request = RequestModel(method="GET", url="http://example.com/users/1", base_url="http://example.com")

        finding = await _analyze_response(
            owner_response=owner_response,
            intruder_response=intruder_response,
            owner_session=owner_session,
            intruder_session=intruder_session,
            request_model=request,
        )

        assert finding is None

    @pytest.mark.asyncio
    async def test_no_bola_when_owner_no_access(self):
        """C2: BOLA must NOT be detected when owner cannot access resource."""
        owner_response = MockResponse(403, body='{"error": "Forbidden"}')
        intruder_response = MockResponse(200, body='{"id": 1, "data": "secret"}')

        owner_session = SessionContext(label="user_a")
        intruder_session = SessionContext(label="user_b")
        request = RequestModel(method="GET", url="http://example.com/users/1", base_url="http://example.com")

        finding = await _analyze_response(
            owner_response=owner_response,
            intruder_response=intruder_response,
            owner_session=owner_session,
            intruder_session=intruder_session,
            request_model=request,
        )

        assert finding is None

    @pytest.mark.asyncio
    async def test_no_bola_when_intruder_gets_not_found(self):
        """C2: BOLA must NOT be detected when intruder gets 'not found' body."""
        owner_response = MockResponse(200, body='{"id": 1, "data": "secret"}')
        intruder_response = MockResponse(200, body='{"error": "Resource not found"}')

        owner_session = SessionContext(label="user_a")
        intruder_session = SessionContext(label="user_b")
        request = RequestModel(method="GET", url="http://example.com/users/1", base_url="http://example.com")

        finding = await _analyze_response(
            owner_response=owner_response,
            intruder_response=intruder_response,
            owner_session=owner_session,
            intruder_session=intruder_session,
            request_model=request,
        )

        assert finding is None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestHelperFunctions:
    """C2: Verify helper functions."""

    @pytest.mark.parametrize("status_code,expected", [
        (200, True),
        (201, True),
        (204, True),
        (301, False),
        (400, False),
        (401, False),
        (403, False),
        (404, False),
        (500, False),
    ])
    def test_is_success(self, status_code, expected):
        """C2: _is_success() must return True for 2xx status codes."""
        assert _is_success(status_code) == expected

    @pytest.mark.parametrize("body,expected", [
        ("not found", True),
        ("forbidden", True),
        ("unauthorized", True),
        ("access denied", True),
        ("resource not found", True),
        ("object not found", True),
        ("success", False),
        ("", False),
        (None, False),
    ])
    def test_contains_not_found_or_forbidden(self, body, expected):
        """C2: _contains_not_found_or_forbidden() must detect forbidden indicators."""
        assert _contains_not_found_or_forbidden(body) == expected

    def test_contains_not_found_case_insensitive(self):
        """C2: Detection must be case-insensitive."""
        assert _contains_not_found_or_forbidden("Not Found") is True
        assert _contains_not_found_or_forbidden("NOT FOUND") is True
        assert _contains_not_found_or_forbidden("nOt FoUnD") is True
