"""BOLA check — Broken Object Level Authorization detection.

Tests for BOLA/IDOR by:
  1. Fetching a resource as user A (owner)
  2. Replaying the same request as user B (intruder)
  3. Checking if user B can access user A's resource

Detection logic:
  - Owner fetch returns 2xx → resource exists
  - Intruder fetch returns 2xx + body differs from "not found"/"forbidden" → BOLA finding
  - Intruder fetch returns 403/401/404 → no BOLA (correctly enforced)
  - Intruder fetch returns 2xx + same body as owner → possible BOLA (evidence captured)
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Optional, TYPE_CHECKING

from nagapasha.models.request_model import RequestModel
from nagapasha.session.session_manager import SessionContext, inject_session


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class BolaFinding:
    """A BOLA/IDOR finding.

    Attributes:
        endpoint: The endpoint that was tested
        owner_session: The owner's session label
        intruder_session: The intruder's session label
        owner_response: Owner's response (status, body preview)
        intruder_response: Intruder's response (status, body preview)
        confidence: Confidence score (0.0 - 1.0)
        evidence: Detailed evidence dict
    """

    endpoint: Any  # DiscoveredEndpoint or RequestModel
    owner_session: str
    intruder_session: str
    owner_response: dict[str, Any] = field(default_factory=dict)
    intruder_response: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class BolaCheckResult:
    """Structured output of BOLA check.

    Attributes:
        finding: Optional BolaFinding if BOLA detected
        success: Whether the check completed successfully
        error: Error message if unsuccessful
    """

    finding: Optional[BolaFinding] = None
    success: bool = True
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# BOLA detection logic
# ---------------------------------------------------------------------------


async def check_bola(
    request_model: RequestModel,
    owner_session: SessionContext,
    intruder_session: SessionContext,
    runner: Any,  # HttpRunner
    scope_checker: Optional[Any] = None,
) -> BolaCheckResult:
    """Check for BOLA/IDOR by comparing owner and intruder responses.

    Args:
        request_model: Request to test (with resource ID)
        owner_session: Session of the resource owner
        intruder_session: Session of the intruder
        runner: HttpRunner for executing requests
        scope_checker: Optional ScopeChecker

    Returns:
        BolaCheckResult with finding if BOLA detected
    """
    result = BolaCheckResult()

    try:
        # Step 1: Fetch as owner
        owner_request = inject_session(copy.deepcopy(request_model), owner_session)
        owner_response = await runner.send(owner_request)

        if not _is_success(owner_response.status_code):
            # Owner cannot access resource — not a BOLA testable
            result.success = True
            return result

        # Step 2: Replay as intruder
        intruder_request = inject_session(copy.deepcopy(request_model), intruder_session)
        intruder_response = await runner.send(intruder_request)

        # Step 3: Analyze response
        finding = await _analyze_response(
            owner_response=owner_response,
            intruder_response=intruder_response,
            owner_session=owner_session,
            intruder_session=intruder_session,
            request_model=request_model,
        )

        if finding:
            result.finding = finding
            result.success = True
        else:
            result.success = True

    except Exception as e:
        result.success = False
        result.error = str(e)

    return result


async def _analyze_response(
    owner_response: Any,
    intruder_response: Any,
    owner_session: SessionContext,
    intruder_session: SessionContext,
    request_model: RequestModel,
) -> Optional[BolaFinding]:
    """Analyze owner and intruder responses to detect BOLA.

    Args:
        owner_response: Owner's HttpxResponse
        intruder_response: Intruder's HttpxResponse
        owner_session: Owner's session
        intruder_session: Intruder's session
        request_model: Original request model

    Returns:
        BolaFinding if BOLA detected, else None
    """
    # Check if owner can access resource
    if not _is_success(owner_response.status_code):
        # Owner cannot access resource — not a BOLA testable
        return None

    # Check if intruder got access
    if not _is_success(intruder_response.status_code):
        # 403/401/404 — correctly enforced, no BOLA
        return None

    # Intruder got 2xx — check if body differs from "not found"/"forbidden"
    intruder_body = intruder_response.body or ""
    if _contains_not_found_or_forbidden(intruder_body):
        return None

    # Intruder got 2xx with actual content — BOLA finding!
    finding = BolaFinding(
        endpoint=request_model,
        owner_session=owner_session.label,
        intruder_session=intruder_session.label,
        owner_response={
            "status_code": owner_response.status_code,
            "body_preview": owner_response.body[:200] if owner_response.body else "",
        },
        intruder_response={
            "status_code": intruder_response.status_code,
            "body_preview": intruder_response.body[:200] if intruder_response.body else "",
        },
        confidence=0.95,
        evidence={
            "owner_access": True,
            "intruder_access": True,
            "intruder_body_differs": True,
        },
    )

    return finding


def _is_success(status_code: int) -> bool:
    """Check if status code indicates success (2xx)."""
    return 200 <= status_code < 300


def _contains_not_found_or_forbidden(body: str) -> bool:
    """Check if response body contains "not found" or "forbidden" indicators."""
    if not body:
        return False

    body_lower = body.lower()
    forbidden_indicators = [
        "not found",
        "forbidden",
        "unauthorized",
        "access denied",
        "resource not found",
        "object not found",
    ]

    for indicator in forbidden_indicators:
        if indicator in body_lower:
            return True

    return False
