"""Response diffing against a baseline fingerprint.

Given a baseline and a new response, compute a delta that identifies:
- Status code changes
- Content-length anomalies
- Response time anomalies
- Reflected payloads
- Known error signatures
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Optional


# Known error-signature regexes (SQL errors, stack traces, path disclosure)
ERROR_SIGNATURES = [
    re.compile(r"(?i)sql\s*(syntax|error|exception|injection)", re.DOTALL),
    re.compile(r"(?i)mysql_fetch|mysql_num_rows|mysql_query", re.DOTALL),
    re.compile(r"(?i)pg_\w+\(\):.*?\[", re.DOTALL),
    re.compile(r"(?i)unclosed\s*quotation\s*mark", re.DOTALL),
    re.compile(r"(?i)ORA-\d{5}", re.DOTALL),
    re.compile(r"(?i)database\s*(error|exception|connection)", re.DOTALL),
    re.compile(r"(?i)stack\s*trace", re.DOTALL),
    re.compile(r"(?i)Traceback\s*\(", re.DOTALL),
    re.compile(r"(?i)Fatal\s*error", re.DOTALL),
    re.compile(r"(?i)class\s+\w+Exception", re.DOTALL),
    re.compile(r"(?i)permission\s*denied.*?(read|write|access)", re.DOTALL),
    re.compile(r"(?i)file\s*(does\s*not\s*exist|not\s*found|missing)", re.DOTALL),
    re.compile(r"(?i)include_path.*?\[", re.DOTALL),
    re.compile(r"(?i)allow_url_include", re.DOTALL),
]


@dataclass
class BaselineFingerprint:
    """Normalized baseline for a "happy path" response."""

    status_code: int
    content_length: int
    body_hash: str              # SHA-256 hex digest
    avg_response_time: float    # seconds
    header_names: frozenset[str]  # lowercase header name set
    body_preview: str = ""      # first 200 chars of body

    @property
    def fingerprint_key(self) -> str:
        """Unique key for this baseline (status + body hash)."""
        return f"{self.status_code}:{self.body_hash}"


def compute_fingerprint(
    status_code: int,
    body: str,
    headers: dict[str, str],
    response_time: float,
) -> BaselineFingerprint:
    """Compute a baseline fingerprint from a single response."""
    body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
    header_names = frozenset(k.lower().strip() for k in headers.keys())
    body_preview = body[:200]
    return BaselineFingerprint(
        status_code=status_code,
        content_length=len(body),
        body_hash=body_hash,
        avg_response_time=response_time,
        header_names=header_names,
        body_preview=body_preview,
    )


@dataclass
class ResponseDelta:
    """Delta between a new response and the baseline."""

    is_no_diff: bool = True           # True if response matches baseline
    status_delta: Optional[int] = None    # delta from baseline status
    content_length_delta: int = 0
    response_time_delta: float = 0.0    # seconds
    has_reflected_payload: bool = False
    reflected_text: str = ""
    has_error_signature: bool = False
    error_signature: str = ""
    is_confirmed_hit: bool = False
    is_near_miss: bool = False
    delta_details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_no_diff": self.is_no_diff,
            "status_delta": self.status_delta,
            "content_length_delta": self.content_length_delta,
            "response_time_delta": self.response_time_delta,
            "has_reflected_payload": self.has_reflected_payload,
            "reflected_text": self.reflected_text[:100],
            "has_error_signature": self.has_error_signature,
            "is_confirmed_hit": self.is_confirmed_hit,
            "is_near_miss": self.is_near_miss,
            "delta_details": self.delta_details,
        }


def compute_delta(
    baseline: BaselineFingerprint,
    status_code: int,
    body: str,
    headers: dict[str, str],
    response_time: float,
    payload: str = "",
) -> ResponseDelta:
    """Compute delta between baseline and a new response.

    Args:
        baseline: The captured baseline fingerprint.
        status_code: Status code of the new response.
        body: Body of the new response.
        headers: Headers of the new response.
        response_time: Time taken for the new response.
        payload: The payload that was sent (for reflection detection).
    """
    delta = ResponseDelta()

    new_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
    new_content_length = len(body)
    body_preview = body[:200]
    new_header_names = frozenset(k.lower().strip() for k in headers.keys())

    # Status code delta
    if status_code != baseline.status_code:
        delta.status_delta = status_code - baseline.status_code
        delta.is_no_diff = False
        delta.delta_details.append(
            f"status: {baseline.status_code} → {status_code} (delta={delta.status_delta})"
        )

    # Content-length delta (flag if >10% change)
    if baseline.content_length > 0:
        cl_delta = new_content_length - baseline.content_length
        cl_pct = abs(cl_delta) / baseline.content_length
        if cl_pct > 0.10:
            delta.content_length_delta = cl_delta
            delta.is_no_diff = False
            delta.delta_details.append(
                f"content-length: {baseline.content_length} → {new_content_length} "
                f"({cl_pct:+.0%})"
            )

    # Response time delta (flag if >3x baseline)
    if baseline.avg_response_time > 0:
        time_ratio = response_time / baseline.avg_response_time
        if time_ratio > 3.0:
            delta.response_time_delta = response_time - baseline.avg_response_time
            delta.is_no_diff = False
            delta.delta_details.append(
                f"response-time: {baseline.avg_response_time:.3f}s → "
                f"{response_time:.3f}s ({time_ratio:.1f}x)"
            )

    # Body hash change
    if new_hash != baseline.body_hash:
        delta.is_no_diff = False

    # Reflected payload detection
    if payload and body:
        # Check raw and lightly-encoded forms
        import urllib.parse
        url_encoded = urllib.parse.quote(payload, safe="")
        check_strings = [payload, url_encoded, payload.lower()]
        body_lower = body.lower()
        for check in check_strings:
            if check and check.lower() in body_lower:
                delta.has_reflected_payload = True
                delta.reflected_text = check[:80]
                delta.is_no_diff = False
                delta.delta_details.append(
                    f"reflected: payload visible in response"
                )
                break

    # Error signature detection
    for sig in ERROR_SIGNATURES:
        if sig.search(body):
            delta.has_error_signature = True
            delta.is_no_diff = False
            # Store first matching signature
            if not delta.error_signature:
                delta.error_signature = sig.pattern[:80]
            delta.delta_details.append(f"error-signature matched: {sig.pattern[:60]}")
            break

    # Determine hit/near-miss classification
    if delta.is_no_diff:
        return delta

    # Confirmed hit: error signature or payload reflection
    if delta.has_error_signature or delta.has_reflected_payload:
        delta.is_confirmed_hit = True

    # Near-miss: status code changed but no error/reflection
    # OR large content-length change without clear error
    elif delta.status_delta is not None and not delta.has_error_signature:
        if delta.status_delta < 0 or delta.status_delta > 100:
            delta.is_near_miss = True

    # Large response-time spike (possible blind SQLi)
    elif delta.response_time_delta > 0 and delta.response_time_delta > 1.0:
        delta.is_near_miss = True

    return delta


def check_flakiness(fingerprints: list[BaselineFingerprint]) -> tuple[bool, str]:
    """Check if multiple baseline fingerprints are consistent.

    Returns (is_flaky, reason).
    If flaky, warn the user that diff-based detection may be noisy.
    """
    if len(fingerprints) < 2:
        return False, ""

    statuses = {fp.status_code for fp in fingerprints}
    hashes = {fp.body_hash for fp in fingerprints}
    times = [fp.avg_response_time for fp in fingerprints]
    avg_time = sum(times) / len(times) if times else 0
    max_time_deviation = max(abs(t - avg_time) for t in times) if times else 0

    if len(statuses) > 1:
        return True, (
            f"status codes varied: {sorted(statuses)}. "
            "Diff-based detection will be noisy."
        )

    if len(hashes) > 1:
        return True, (
            f"body hashes varied ({len(hashes)} unique). "
            "The response is not deterministic."
        )

    if avg_time > 0 and max_time_deviation > avg_time * 0.5:
        return True, (
            f"response times vary widely (max deviation: {max_time_deviation:.3f}s "
            f"from mean {avg_time:.3f}s). "
            "Timing-based detection may have false positives."
        )

    return False, ""
