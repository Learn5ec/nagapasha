"""Phase D — App-wide DAST orchestration.

Ties together:
  - B1: OpenAPI ingestion → list[DiscoveredEndpoint]
  - B3: Target deduplication → deduplicated list[DiscoveredEndpoint]
  - C1: Session establishment → list[SessionContext]
  - C2: BOLA checks → list[BolaFinding]
  - Phase A: Single-endpoint scanning → list[Finding]

Pipeline:
  1. Parse OpenAPI spec(s) → list[DiscoveredEndpoint]
  2. Deduplicate endpoints → deduplicated list[DiscoveredEndpoint]
  3. For each endpoint:
     a. If auth required: establish sessions (owner, intruder)
     b. If 2+ sessions: run BOLA check
     c. Run Phase A scan (with session injection if authenticated)
  4. Aggregate findings, report

Usage:
  async def main():
      orchestrator = DiscoverAndScanOrchestrator(
          session_manager=...,
          runner=HttpRunner(...),
          scope_checker=ScopeChecker(...),
      )
      results = await orchestrator.run(spec_urls=["https://api.example.com/openapi.json"])
      for finding in results.findings:
          print(finding)
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, TYPE_CHECKING

from nagapasha.stages.stage09_openapi import (
    parse_openapi_spec,
    OpenAPIParseResult,
    DiscoveredEndpoint,
)
from nagapasha.stages.stage13_target_dedup import deduplicate_endpoints, DeduplicationResult
from nagapasha.session.session_manager import (
    SessionContext,
    SessionEstablishmentResult,
    establish_session,
    inject_session,
    is_session_valid,
)
from nagapasha.engine.bola_check import (
    check_bola,
    BolaCheckResult,
    BolaFinding,
)
from nagapasha.models.request_model import RequestModel, ParameterModel
from nagapasha.engine.runner import HttpRunner, HttpxResponse


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """A single scan result (finding or no-finding) for an endpoint."""

    endpoint: DiscoveredEndpoint
    session_label: Optional[str]  # None if no session (public endpoint)
    baseline: Optional[dict[str, Any]] = None  # P1-1: fresh baseline for this scan
    findings: list[dict[str, Any]] = field(default_factory=list)
    total_fired: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class BolaResult:
    """BOLA check result for an endpoint."""

    endpoint: DiscoveredEndpoint
    owner_session: str
    intruder_session: str
    finding: Optional[BolaFinding] = None
    error: Optional[str] = None


@dataclass
class AppWideScanResult:
    """Aggregated results from scanning an entire app."""

    scan_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_end: Optional[datetime] = None

    # OpenAPI results
    openapi_results: list[OpenAPIParseResult] = field(default_factory=list)
    dedup_result: Optional[DeduplicationResult] = None

    # Session results
    sessions: list[SessionContext] = field(default_factory=list)

    # BOLA results
    bola_results: list[BolaResult] = field(default_factory=list)

    # Scan results (Phase A)
    scan_results: list[ScanResult] = field(default_factory=list)

    # Aggregated findings
    findings: list[dict[str, Any]] = field(default_factory=list)

    # Metadata
    spec_urls: list[str] = field(default_factory=list)
    total_endpoints: int = 0
    total_sessions: int = 0
    total_bola_checks: int = 0
    total_findings: int = 0
    total_errors: int = field(default_factory=list)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class DiscoverAndScanOrchestrator:
    """Orchestrates app-wide DAST scanning.

    Attributes:
        session_manager: Optional custom session manager (for testing)
        runner: HttpRunner for executing requests
        scope_checker: ScopeChecker for authorization gating
        rate_limit: Rate limit config
        max_sessions: Max number of sessions to establish
        max_requests: Hard cap on total requests
    """

    def __init__(
        self,
        runner: HttpRunner,
        scope_checker: Any = None,
        rate_limit: Optional[dict[str, Any]] = None,
        max_sessions: int = 5,
        max_requests: int = 10000,
    ):
        self.runner = runner
        self.scope_checker = scope_checker
        self.rate_limit = rate_limit
        self.max_sessions = max_sessions
        self.max_requests = max_requests

    async def run(
        self,
        spec_urls: list[str],
        login_curls: Optional[dict[str, str]] = None,
    ) -> AppWideScanResult:
        """Run the full app-wide scan pipeline.

        Args:
            spec_urls: List of OpenAPI spec URLs or file paths
            login_curls: Optional dict of session labels → login curl commands

        Returns:
            AppWideScanResult with aggregated findings
        """
        result = AppWideScanResult()
        result.spec_urls = spec_urls

        # Step 1: Parse OpenAPI specs
        console.print("[bold]Step 1: Parsing OpenAPI specs...[/bold]")
        for spec_url in spec_urls:
            console.print(f"  Parsing: {spec_url}")
            try:
                openapi_result = await parse_openapi_spec(
                    spec_source=spec_url,
                    scope_checker=self.scope_checker,
                )
                result.openapi_results.append(openapi_result)
                console.print(f"    Found {len(openapi_result.endpoints)} endpoint(s)")
            except Exception as e:
                result.total_errors.append(f"Failed to parse {spec_url}: {e}")
                console.print(f"  [red]Failed:[/red] {e}")

        # Step 2: Deduplicate endpoints
        console.print("[bold]Step 2: Deduplicating endpoints...[/bold]")
        all_endpoints = []
        for openapi_result in result.openapi_results:
            all_endpoints.extend(openapi_result.endpoints)

        if all_endpoints:
            result.dedup_result = deduplicate_endpoints(all_endpoints)
            result.total_endpoints = result.dedup_result.deduped_count
            console.print(
                f"  {result.dedup_result.original_count} → {result.dedup_result.deduped_count} "
                f"(removed {result.dedup_result.removed_count})"
            )
        else:
            result.dedup_result = DeduplicationResult(endpoints=[])
            console.print("  No endpoints found.")

        # Step 3: Establish sessions
        console.print("[bold]Step 3: Establishing sessions...[/bold]")
        if login_curls:
            for label, curl in login_curls.items():
                if len(result.sessions) >= self.max_sessions:
                    console.print(f"  Max sessions reached ({self.max_sessions})")
                    break

                console.print(f"  Establishing session: {label}")
                try:
                    session_result = await establish_session(
                        login_curl=curl,
                        scope_checker=self.scope_checker,
                        label=label,
                    )
                    if session_result.success and session_result.session:
                        result.sessions.append(session_result.session)
                        console.print(f"    Session established: {label}")
                    else:
                        console.print(f"    [red]Failed:[/red] {session_result.error}")
                except Exception as e:
                    result.total_errors.append(f"Failed to establish session {label}: {e}")
                    console.print(f"  [red]Error:[/red] {e}")

        result.total_sessions = len(result.sessions)
        console.print(f"  Established {len(result.sessions)} session(s)")

        # Step 4: Run BOLA checks (if 2+ sessions)
        console.print("[bold]Step 4: Running BOLA checks...[/bold]")
        if len(result.sessions) >= 2:
            for endpoint in result.dedup_result.endpoints:
                # Check if endpoint requires auth
                if "auth" not in endpoint.risk_tags:
                    continue

                # Run BOLA check for each session pair
                for i, owner_session in enumerate(result.sessions):
                    for intruder_session in result.sessions[i + 1:]:
                        bola_result = await self._run_bola_check(
                            endpoint=endpoint,
                            owner_session=owner_session,
                            intruder_session=intruder_session,
                        )
                        result.bola_results.append(bola_result)
                        result.total_bola_checks += 1

                        if bola_result.finding:
                            console.print(
                                f"  [red]BOLA finding:[/red] {endpoint.method} {endpoint.path_template} "
                                f"({owner_session.label} → {intruder_session.label})"
                            )
                            result.findings.append(bola_result.finding)
                        elif bola_result.error:
                            console.print(f"  [yellow]BOLA error:[/yellow] {bola_result.error}")
        else:
            console.print("  Skipping BOLA: need 2+ sessions")

        # Step 5: Run Phase A scans
        console.print("[bold]Step 5: Running Phase A scans...[/bold]")
        for endpoint in result.dedup_result.endpoints:
            # Create a RequestModel from the endpoint
            request = self._endpoint_to_request(endpoint)

            # Scan with each session (and no session for public endpoints)
            sessions_to_scan = [None] + result.sessions
            for session in sessions_to_scan:
                scan_result = await self._run_phase_a_scan(
                    request=request,
                    session=session,
                )
                result.scan_results.append(scan_result)
                result.findings.extend(scan_result.findings)
                result.total_findings += len(scan_result.findings)

        result.scan_end = datetime.now(timezone.utc)
        console.print(f"\n[bold]Scan complete:[/bold] {result.total_findings} finding(s)")

        return result

    async def _run_bola_check(
        self,
        endpoint: DiscoveredEndpoint,
        owner_session: SessionContext,
        intruder_session: SessionContext,
    ) -> BolaResult:
        """Run a BOLA check for a single endpoint/session pair."""
        result = BolaResult(
            endpoint=endpoint,
            owner_session=owner_session.label,
            intruder_session=intruder_session.label,
        )

        try:
            request = self._endpoint_to_request(endpoint)
            bola_check_result = await check_bola(
                request_model=request,
                owner_session=owner_session,
                intruder_session=intruder_session,
                runner=self.runner,
                scope_checker=self.scope_checker,
            )

            if bola_check_result.finding:
                result.finding = bola_check_result.finding
        except Exception as e:
            result.error = str(e)

        return result

    async def _run_phase_a_scan(
        self,
        request: RequestModel,
        session: Optional[SessionContext],
    ) -> ScanResult:
        """Run Phase A scan on a single request (with optional session).

        P1-1: Captures a FRESH baseline per endpoint+session combination rather
        than reusing a shared baseline. This ensures Phase 2 scan deltas are
        computed against the session's actual response shape, not the Phase 1
        baseline which was captured without session injection.

        P1-2: Rate-limiter state carries forward automatically since the runner
        is shared across all scans — no new runner is created per scan.
        """
        # Determine session label
        session_label = session.label if session else None

        # Inject session if present
        if session:
            request = inject_session(request, session)

        # P1-1: Capture a fresh baseline for this endpoint+session combination.
        # Each scan needs its own baseline because session-injected responses
        # have different shapes than pre-session responses.
        try:
            from nagapasha.engine.baseline import capture_baseline
            baseline, is_flaky, flakiness_reason = await capture_baseline(
                runner=self.runner,
                request_model=request,
                count=3,  # Light baseline: 3 fires (vs 5 in payload loop)
            )
            if is_flaky:
                self.runner.logger.warning(
                    f"Baseline flaky for {request.method} {request.url} "
                    f"(session={session_label}): {flakiness_reason}"
                )
        except Exception as e:
            baseline = None
            self.runner.logger.warning(
                f"Failed to capture baseline for {request.method} {request.url}: {e}"
            )

        # Create scan result
        endpoint = DiscoveredEndpoint(
            method=request.method,
            path_template=request.url,
            concrete_path=request.url,
            parameters=request.parameters,
            base_url=request.base_url,
        )
        scan_result = ScanResult(
            endpoint=endpoint,
            session_label=session_label,
            baseline=baseline,  # P1-1: per-scan baseline
        )

        try:
            # TODO: Implement payload firing loop
            # This would call the payload loop with the request and baseline
            pass
        except Exception as e:
            scan_result.errors.append(str(e))
            self.runner.logger.warning(f"Scan failed for {request.method} {request.url}: {e}")

        return scan_result

    def _endpoint_to_request(self, endpoint: DiscoveredEndpoint) -> RequestModel:
        """Convert a DiscoveredEndpoint to a RequestModel."""
        return RequestModel(
            method=endpoint.method,
            url=endpoint.full_url(),
            base_url=endpoint.base_url or "",
            parameters=endpoint.parameters,
        )


# ---------------------------------------------------------------------------
# Console helper (for non-Typer usage)
# ---------------------------------------------------------------------------


class _SimpleConsole:
    """Simple console for logging (used when Typer is not available)."""

    def print(self, message: str):
        print(message)


console = _SimpleConsole()
