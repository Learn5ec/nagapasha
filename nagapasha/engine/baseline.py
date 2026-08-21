"""Baseline capture and fingerprinting.

Fire the happy-path request 3–5 times, capture a normalized response fingerprint.
Also detects flakiness if fingerprints disagree.
"""

from __future__ import annotations

from typing import Optional

from nagapasha.engine.diff import BaselineFingerprint, compute_fingerprint, check_flakiness
from nagapasha.engine.runner import HttpRunner
from nagapasha.models.request_model import RequestModel


async def capture_baseline(
    runner: HttpRunner,
    request_model: RequestModel,
    count: int = 5,
) -> tuple[BaselineFingerprint, bool, str]:
    """Capture a baseline fingerprint by firing the request N times.

    Args:
        runner: HTTP runner with rate limiter.
        request_model: The request to baseline.
        count: Number of calibration fires (default 5).

    Returns:
        Tuple of (baseline_fingerprint, is_flaky, flakiness_reason).
    """
    responses = await runner.send_multiple(request_model, count=count)

    if not responses:
        raise RuntimeError("No responses captured during baseline calibration")

    # Compute average response time
    avg_time = sum(r.elapsed for r in responses) / len(responses)
    avg_content_length = sum(len(r.body) for r in responses) / len(responses)

    # Use the first response as the primary fingerprint
    # (assume first response is typical for a stable target)
    fingerprint = compute_fingerprint(
        status_code=responses[0].status_code,
        body=responses[0].body,
        headers=responses[0].headers,
        response_time=avg_time,
    )

    # Update content_length to average across all calibrations
    fingerprint.content_length = int(avg_content_length)

    # Check flakiness
    fingerprints = [
        compute_fingerprint(
            status_code=r.status_code,
            body=r.body,
            headers=r.headers,
            response_time=r.elapsed,
        )
        for r in responses
    ]
    is_flaky, reason = check_flakiness(fingerprints)

    return fingerprint, is_flaky, reason
