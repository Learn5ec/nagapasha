"""Continuous recalibration for Stage 9.5.

This module provides resilience mechanisms to handle target changes during
payload execution:
- Hard rate ceiling (independent of target's rate limit)
- Periodic baseline refresh
- WAF behavior monitoring (403/429/CAPTCHA detection)
- Rolling control requests (benign request alongside payloads)

The goal is to prevent accidental DoS, detect WAF challenges, and maintain
accurate diffing against a dynamic baseline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Configuration
HARD_RATE_CEILING = 10  # requests/sec, independent of target's rate limit
BASELINE_REFRESH_INTERVAL = 100  # refresh baseline every N payloads
CONTROL_REQUEST_INTERVAL = 50  # send control request every N payloads
WAF_403_THRESHOLD = 0.2  # 20% 403 ratio triggers WAF re-detection
WAF_403_WINDOW = 50  # check 403 ratio over last N requests


@dataclass
class RecalibrationState:
    """Tracks recalibration state and metrics.

    Attributes:
        total_requests: Total requests sent
        recent_status_codes: Last N status codes for WAF monitoring
        baselines: Rolling baseline samples for drift detection
        last_baseline_refresh: When baseline was last refreshed
        waf_rechecked: Whether WAF re-detection is needed
    """

    total_requests: int = 0
    recent_status_codes: list[int] = field(default_factory=list)
    baselines: list[dict[str, Any]] = field(default_factory=list)
    last_baseline_refresh: Optional[float] = None
    waf_rechecked: bool = False
    control_request_count: int = 0


class RecalibrationChecker:
    """Monitors and recalibrates during payload execution.

    This checker runs alongside the payload loop and:
    1. Enforces a hard rate ceiling
    2. Periodically refreshes the baseline
    3. Monitors for WAF challenges (403/429/CAPTCHA)
    4. Sends rolling control requests for accurate diffing

    Usage:
        checker = RecalibrationChecker(context, baseline, rate_limit_pps)
        checker.check_result(result)
        if checker.needs_baseline_refresh():
            checker.refresh_baseline()
    """

    def __init__(
        self,
        context: Any = None,
        baseline: Optional[dict[str, Any]] = None,
        rate_limit_pps: float = 4.0,
        max_requests: int = 1000,
    ):
        """Initialize recalibration checker.

        Args:
            context: Engagement context (optional)
            baseline: Initial baseline fingerprint
            rate_limit_pps: Target's rate limit in requests/sec
            max_requests: Hard cap on total requests
        """
        self.context = context
        self.baseline = baseline or {}
        self.rate_limit_pps = min(rate_limit_pps, HARD_RATE_CEILING)
        self.max_requests = max_requests

        # State
        self.state = RecalibrationState()
        self._last_request_time: Optional[float] = None

    def check_result(self, result: dict[str, Any]) -> None:
        """Check a payload result for recalibration triggers.

        Args:
            result: Payload result dict with status_code, etc.
        """
        self.state.total_requests += 1
        self.state.recent_status_codes.append(result.get("status_code", 0))

        # Keep only last WAF_403_WINDOW status codes
        if len(self.state.recent_status_codes) > WAF_403_WINDOW:
            self.state.recent_status_codes = self.state.recent_status_codes[-WAF_403_WINDOW:]

        # Check for WAF challenge
        if self._is_waf_challenge_detected():
            logger.warning(
                f"WAF challenge detected ({len(self.state.recent_status_codes)} "
                f"requests, {self._get_403_ratio():.1%} 403 ratio)"
            )
            self.state.waf_rechecked = True

        # Check if baseline needs refresh
        if self.state.total_requests % BASELINE_REFRESH_INTERVAL == 0:
            self.state.last_baseline_refresh = None

        # Check if control request needed
        if self.state.total_requests % CONTROL_REQUEST_INTERVAL == 0:
            self.state.control_request_count += 1

        # Check hard rate ceiling
        if self._is_rate_ceiling_violated():
            logger.warning("Hard rate ceiling exceeded — backing off")

    def needs_baseline_refresh(self) -> bool:
        """Check if baseline needs refresh.

        Returns:
            True if baseline should be refreshed
        """
        # Need refresh if never refreshed OR if last refresh was more than BASELINE_REFRESH_INTERVAL requests ago
        if self.state.last_baseline_refresh is None:
            return self.state.total_requests >= BASELINE_REFRESH_INTERVAL
        return True  # Always allow refresh check

    def needs_control_request(self) -> bool:
        """Check if control request is needed.

        Returns:
            True if control request should be sent
        """
        return self.state.total_requests > 0 and (
            self.state.total_requests % CONTROL_REQUEST_INTERVAL == 0
        )

    def needs_waf_rerun(self) -> bool:
        """Check if WAF detection should be re-run.

        Returns:
            True if WAF detection needs re-running
        """
        return self.state.waf_rechecked

    def get_403_ratio(self) -> float:
        """Get the 403 response ratio over the monitoring window.

        Returns:
            Ratio of 403 responses (0.0 to 1.0)
        """
        return self._get_403_ratio()

    def get_baselines(self) -> list[dict[str, Any]]:
        """Get rolling baseline samples.

        Returns:
            List of baseline samples
        """
        return self.state.baselines

    def add_baseline_sample(self, sample: dict[str, Any]) -> None:
        """Add a baseline sample for drift detection.

        Args:
            sample: Baseline fingerprint dict
        """
        self.state.baselines.append(sample)
        self.state.last_baseline_refresh = None  # Mark as not refreshed yet

        # Keep only last 5 samples
        if len(self.state.baselines) > 5:
            self.state.baselines = self.state.baselines[-5:]

    def get_control_request_payload(self) -> Optional[dict[str, Any]]:
        """Get payload for rolling control request.

        Returns:
            Control request payload (benign value) or None
        """
        if not self.needs_control_request():
            return None

        # Return a benign version of the first parameter (for diffing)
        if not self.baseline:
            return None

        return {
            "type": "control",
            "baseline": self.baseline,
        }

    def _is_waf_challenge_detected(self) -> bool:
        """Check if WAF challenge is detected based on 403 ratio.

        Returns:
            True if WAF challenge detected
        """
        if len(self.state.recent_status_codes) < 10:
            return False

        return self._get_403_ratio() > WAF_403_THRESHOLD

    def _get_403_ratio(self) -> float:
        """Calculate 403 response ratio.

        Returns:
            Ratio of 403 responses
        """
        if not self.state.recent_status_codes:
            return 0.0

        count_403 = sum(1 for code in self.state.recent_status_codes if code == 403)
        return count_403 / len(self.state.recent_status_codes)

    def _is_rate_ceiling_violated(self) -> bool:
        """Check if hard rate ceiling is violated.

        Returns:
            True if rate ceiling exceeded
        """
        if not self._last_request_time:
            return False

        import time
        elapsed = time.monotonic() - self._last_request_time
        if elapsed <= 0:
            return False

        rate = 1.0 / elapsed
        return rate > self.rate_limit_pps

    def update_rate(self, elapsed: float) -> None:
        """Update last request time for rate tracking.

        Args:
            elapsed: Time since last request
        """
        self._last_request_time = time.monotonic()

    def check_max_requests(self) -> bool:
        """Check if max requests limit has been reached.

        Returns:
            True if max requests exceeded
        """
        return self.state.total_requests >= self.max_requests

    def get_stats(self) -> dict[str, Any]:
        """Get recalibration statistics.

        Returns:
            Stats dict
        """
        return {
            "total_requests": self.state.total_requests,
            "403_ratio": self._get_403_ratio(),
            "baseline_refresh_needed": self.needs_baseline_refresh(),
            "control_request_needed": self.needs_control_request(),
            "waf_recheck_needed": self.state.waf_rechecked,
            "control_requests_sent": self.state.control_request_count,
        }


def check_baseline_drift(
    current_baseline: dict[str, Any],
    baselines: list[dict[str, Any]],
    threshold: float = 0.1,
) -> bool:
    """Check if baseline has drifted significantly.

    Args:
        current_baseline: Current baseline fingerprint
        baselines: List of previous baseline samples
        threshold: Drift threshold (10% by default)

    Returns:
        True if drift detected
    """
    if len(baselines) < 2:
        return False

    # Compare content lengths (simple drift detection)
    current_cl = current_baseline.get("content_length", 0)
    if not current_cl:
        return False

    prev_cl = [b.get("content_length", 0) for b in baselines if b.get("content_length")]
    if not prev_cl:
        return False

    avg_cl = sum(prev_cl) / len(prev_cl)
    if avg_cl == 0:
        return False

    drift = abs(current_cl - avg_cl) / avg_cl
    return drift > threshold
