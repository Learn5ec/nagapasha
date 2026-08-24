"""Triage engine — heuristic pass on every response.

Classifies each response as:
  - HIT: clear positive signal (error signature, payload reflection)
  - NO-DIFF: matches baseline
  - AMBIGUOUS: some signal but not confirmed (queued for Specialist)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from nagapasha.engine.diff import (
    BaselineFingerprint,
    ResponseDelta,
    compute_delta,
)


@dataclass
class TriageResult:
    """Result of triage classification for a single response."""

    is_hit: bool = False
    is_no_diff: bool = True
    is_ambiguous: bool = False
    is_rejected: bool = False  # 400-class response indicates server rejection
    confidence: float = 0.0  # 0.0 - 1.0
    evidence: list[str] = field(default_factory=list)
    delta: Optional[ResponseDelta] = None

    def to_dict(self) -> dict[str, str]:
        return {
            "is_hit": str(self.is_hit),
            "is_no_diff": str(self.is_no_diff),
            "is_ambiguous": str(self.is_ambiguous),
            "is_rejected": str(self.is_rejected),
            "confidence": f"{self.confidence:.2f}",
            "evidence": "; ".join(self.evidence),
        }


def triage(
    baseline: BaselineFingerprint,
    status_code: int,
    body: str,
    headers: dict[str, str],
    response_time: float,
    payload: str = "",
) -> TriageResult:
    """Run heuristic triage on a single response.

    Args:
        baseline: The baseline fingerprint.
        status_code: Response status code.
        body: Response body.
        headers: Response headers.
        response_time: Response time in seconds.
        payload: The payload that was sent.

    Returns:
        TriageResult with classification.
    """
    delta = compute_delta(
        baseline=baseline,
        status_code=status_code,
        body=body,
        headers=headers,
        response_time=response_time,
        payload=payload,
    )

    result = TriageResult(delta=delta)
    result.is_no_diff = delta.is_no_diff

    # Check for rejected responses (400-class status codes)
    if 400 <= status_code < 500 and status_code != 401 and status_code != 403:
        # 400, 404, 405, etc. indicate server rejected the payload
        # (but exclude 401/403 which are auth issues)
        result.is_rejected = True
        result.confidence = 0.90
        result.evidence.append(f"rejected: {status_code}")
        return result

    if delta.is_no_diff:
        result.confidence = 1.0
        return result

    # Clear hits
    if delta.has_error_signature:
        result.is_hit = True
        result.confidence = 0.95
        result.evidence.append(f"error-signature: {delta.error_signature}")
        return result

    if delta.has_reflected_payload:
        result.is_hit = True
        result.confidence = 0.90
        result.evidence.append(f"reflected: {delta.reflected_text[:50]}")
        return result

    # Strong signals
    if delta.status_delta is not None:
        # Large status code change (e.g., 200 -> 500)
        if abs(delta.status_delta) >= 100:
            result.is_hit = True
            result.confidence = 0.80
            result.evidence.append(f"status-change: {delta.status_delta:+d}")
            return result

    # Ambiguous: near-miss signals
    if delta.is_near_miss:
        result.is_ambiguous = True
        result.confidence = 0.50

        if delta.status_delta is not None:
            result.evidence.append(f"status-delta: {delta.status_delta:+d}")
        if delta.content_length_delta:
            result.evidence.append(
                f"content-length-delta: {delta.content_length_delta}"
            )
        if delta.response_time_delta > 0:
            result.evidence.append(
                f"response-time-spike: +{delta.response_time_delta:.3f}s"
            )
        return result

    # No clear signal but body changed
    result.is_ambiguous = True
    result.confidence = 0.30
    result.evidence.append("body-changed")
    return result
