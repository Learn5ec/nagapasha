"""Timing-anomaly detection for blind/time-based injection.

Monitors response times and flags outliers relative to a rolling baseline.
Used to detect blind injection by its side effect (executing a delay) rather
than by its cause (a specific payload string).

Design: maintains a rolling window of recent response times (from non-payload
baseline requests). When a payload is fired, checks whether its elapsed time
is anomalous relative to both the baseline average AND the rolling mean.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TimingCheck:
    """Result of a timing anomaly check."""

    anomalous: bool = False
    delay_magnitude: float = 0.0  # seconds above baseline
    baseline_avg: float = 0.0
    current_elapsed: float = 0.0
    details: list[str] = field(default_factory=list)


class TimingMonitor:
    """Tracks response times and detects timing anomalies.

    Usage:
        monitor = TimingMonitor(window_size=10)
        monitor.record_baseline(elapsed=0.2)   # call for baseline requests
        check = monitor.check(payload_elapsed=1.5)
        if check.anomalous:
            print(f"Timing anomaly: +{check.delay_magnitude:.3f}s")
    """

    def __init__(self, window_size: int = 10) -> None:
        self._window: deque[float] = deque(maxlen=window_size)
        self._baseline_avg: Optional[float] = None
        self._min_samples = 3  # need at least 3 baseline samples to be meaningful

    def record_baseline(self, elapsed: float) -> None:
        """Record a non-payload response time as baseline data."""
        self._window.append(elapsed)
        if self._window:
            self._baseline_avg = sum(self._window) / len(self._window)

    def reset(self) -> None:
        """Clear the rolling window."""
        self._window.clear()
        self._baseline_avg = None

    def check(self, payload_elapsed: float) -> TimingCheck:
        """Check if a payload response time is anomalous.

        Args:
            payload_elapsed: Elapsed time for the payload request.

        Returns:
            TimingCheck with anomalous=True if the payload took significantly
            longer than baseline.
        """
        result = TimingCheck(current_elapsed=payload_elapsed)

        if self._baseline_avg is None or len(self._window) < self._min_samples:
            # Not enough baseline data to determine anomaly
            result.details.append("insufficient baseline data")
            return result

        # Compute rolling mean (exclude the current baseline_avg, use window only)
        if len(self._window) >= 2:
            rolling_mean = sum(self._window) / len(self._window)
        else:
            rolling_mean = self._baseline_avg

        result.baseline_avg = self._baseline_avg

        # Check against both baseline average and rolling mean
        baseline_ratio = payload_elapsed / self._baseline_avg if self._baseline_avg > 0 else 0
        rolling_ratio = payload_elapsed / rolling_mean if rolling_mean > 0 else 0

        # Flag if >3x baseline AND >2x rolling mean
        if baseline_ratio > 3.0 and rolling_ratio > 2.0:
            result.anomalous = True
            result.delay_magnitude = payload_elapsed - self._baseline_avg
            result.details.append(
                f"timing anomaly: {payload_elapsed:.3f}s vs "
                f"baseline {self._baseline_avg:.3f}s ({baseline_ratio:.1f}x)"
            )
        elif baseline_ratio > 3.0:
            result.anomalous = True
            result.delay_magnitude = payload_elapsed - self._baseline_avg
            result.details.append(
                f"timing anomaly: {payload_elapsed:.3f}s vs "
                f"baseline {self._baseline_avg:.3f}s ({baseline_ratio:.1f}x)"
            )

        return result
