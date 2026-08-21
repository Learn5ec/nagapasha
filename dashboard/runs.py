"""In-memory active run tracker for the dashboard.

Mirrors EngagementStore rows but tracks live execution state (running, paused,
completed, killed) with references to the PayloadLoop for pause/resume control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from nagapasha.engine.payload_loop import PayloadLoop


@dataclass
class ActiveRun:
    """Live execution state for a single engagement."""

    engagement_id: str
    status: str = "running"  # running, paused, completed, killed
    loop: Optional[PayloadLoop] = None
    payload_count: int = 0
    total_fired: int = 0
    hits: int = 0
    near_misses: int = 0
    no_diff: int = 0
    rate_limit_pps: float = 4.0
    rate_limit_burst: float = 10.0
    jwt_expires_at: Optional[float] = None
    request_model: Optional[object] = None  # the RequestModel (not serialized)
    baseline_status_code: Optional[int] = None
    baseline_content_length: Optional[int] = None
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to a JSON-friendly dict for WebSocket pushes."""
        return {
            "engagement_id": self.engagement_id,
            "status": self.status,
            "total_fired": self.total_fired,
            "payload_count": self.payload_count,
            "hits": self.hits,
            "near_misses": self.near_misses,
            "no_diff": self.no_diff,
            "rate_limit_pps": self.rate_limit_pps,
            "rate_limit_burst": self.rate_limit_burst,
            "jwt_expires_at": self.jwt_expires_at,
            "baseline_status_code": self.baseline_status_code,
            "findings": self.findings,
            "progress": (
                round(self.total_fired / self.payload_count * 100, 1)
                if self.payload_count > 0 else 0
            ),
        }


class ActiveRuns:
    """In-memory tracker of currently executing payload loops."""

    def __init__(self) -> None:
        self._runs: dict[str, ActiveRun] = {}

    def start(self, run: ActiveRun) -> None:
        """Register a new active run."""
        self._runs[run.engagement_id] = run

    def get(self, engagement_id: str) -> Optional[ActiveRun]:
        """Get an active run by ID."""
        return self._runs.get(engagement_id)

    def list(self) -> list[ActiveRun]:
        """List all active runs."""
        return list(self._runs.values())

    def pause(self, engagement_id: str) -> bool:
        """Pause a running engagement. Returns True if successful."""
        run = self._runs.get(engagement_id)
        if not run or run.status != "running" or run.loop is None:
            return False
        if run.loop.pause():
            run.status = "paused"
            return True
        return False

    def resume(self, engagement_id: str) -> bool:
        """Resume a paused engagement. Returns True if successful."""
        run = self._runs.get(engagement_id)
        if not run or run.status != "paused" or run.loop is None:
            return False
        if run.loop.resume():
            run.status = "running"
            return True
        return False

    def kill(self, engagement_id: str) -> bool:
        """Kill a running/paused engagement. Returns True if successful."""
        run = self._runs.get(engagement_id)
        if not run or run.status in ("completed", "killed"):
            return False
        if run.loop:
            run.loop.kill_and_reset()
        run.status = "killed"
        return True

    def complete(self, engagement_id: str, results: dict) -> None:
        """Mark a run as completed and update stats."""
        run = self._runs.get(engagement_id)
        if run:
            run.status = "completed"
            run.total_fired = results.get("total_fired", 0)
            run.hits = results.get("hits", 0)
            run.near_misses = results.get("near_misses", 0)
            run.no_diff = results.get("no_diff", 0)

    def remove(self, engagement_id: str) -> None:
        """Remove a run (called when the loop finishes)."""
        self._runs.pop(engagement_id, None)

    def add_finding(self, engagement_id: str, finding: dict) -> None:
        """Add a finding to an active run's findings list."""
        run = self._runs.get(engagement_id)
        if run:
            run.findings.append(finding)
