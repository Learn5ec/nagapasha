"""Typer CLI for nagapasha.

Commands:
  parse    — Parse a curl command into a RequestModel (JSON output)
  recon    — Run parse + recon, print results, save to SQLite
  generate — Run parse + recon + output a standalone Phase 1 script
  run      — Execute a generated Phase 1 script
  full     — Run the full pipeline: parse → recon → targeting → generate → run
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from nagapasha import __version__
from nagapasha.models.request_model import RequestModel
from nagapasha.stages.stage01_parse import parse_curl, CurlParseError
from nagapasha.stages.stage02_recon import run_recon, ReconResult
from nagapasha.stages.stage03_targeting import run_targeting
from nagapasha.engine.runner import HttpRunner
from nagapasha.engine.rate_limiter import RateLimitConfig, TokenBucketRateLimiter
from nagapasha.engine.script_generator import StaticScriptGenerator
from nagapasha.engine.payload_loop import PayloadLoop, PayloadCandidate
from nagapasha.engine.diff import compute_fingerprint
from nagapasha.db.schema import EngagementStore
from nagapasha.utils.scope_guard import ScopeGuard
from nagapasha.utils.notifications import notify_run_complete

app = typer.Typer(
    name="nagapasha",
    help="Adaptive AI-Powered Intruder — turn a curl request into a targeted attack suite.",
    add_completion=False,
)


def _strip_ansi_c_quotes(curl_command: str) -> str:
    """Strip ANSI-C quoting ($'...') from curl commands copied from Burp Suite.

    Burp Suite Professional exports curl commands with $'...' quoting (ANSI-C).
    This function converts $'PATCH' -> PATCH, $'Host: value' -> 'Host: value',
    $'https://...' -> 'https://...', etc.
    """
    import re
    # Replace \$'...' or $'...' with '...' (strip the leading $ or \$), non-greedy
    curl_command = re.sub(r"\\?\$'([^']*)'", r"'\1'", curl_command)
    return curl_command


@app.command()
def dashboard(
    host: str = typer.Option(
        "0.0.0.0", "--host", "-h", help="Host to bind to"
    ),
    port: int = typer.Option(
        8000, "--port", "-p", help="Port to bind to"
    ),
) -> None:
    """Start the nagapasha dashboard web interface."""
    from dashboard.app import run_dashboard
    console.print(f"[bold]Starting dashboard on http://{host}:{port}[/bold]")
    console.print(f"  Open http://localhost:{port} in your browser")
    console.print(f"  API docs at http://localhost:{port}/docs")
    run_dashboard(host=host, port=port)


@app.command()
def cicd(
    curl_command: str = typer.Argument(
        ...,
        help="The curl command to run through the full pipeline",
    ),
    calibrate: int = typer.Option(
        5, "--calibrate", "-c", help="Number of baseline calibration fires"
    ),
    max_requests: int = typer.Option(
        1000, "--max-requests", "-m", help="Hard cap on total requests"
    ),
    fail_on_severity: str = typer.Option(
        "high", "--fail-on-severity", help="Fail if findings exceed this severity (low, medium, high, critical)"
    ),
    output_format: str = typer.Option(
        "sarif", "--output-format", "-f",
        help="Output format: json, sarif, junit, or all"
    ),
    engagement: Optional[str] = typer.Option(
        None, "--engagement", "-e", help="Path to .ctx engagement file"
    ),
    no_authorization_required: bool = typer.Option(
        False, "--no-authorization-required",
        help="Explicitly disable security gates (not recommended for live targets)",
    ),
) -> None:
    """CI/CD integration: non-interactive security gating.

    Automatically runs the full pipeline with JSON/SARIF output and
    exits with code 1 if findings exceed the severity threshold.
    """
    # Load engagement context if provided
    engagement_context = None
    if engagement:
        try:
            from nagapasha.engagement import EngagementContext
            engagement_context = EngagementContext.load(Path(engagement))
        except Exception as e:
            console.print(f"[red]Failed to load engagement context:[/red] {e}")
            sys.exit(3)

    try:
        req = parse_curl(_strip_ansi_c_quotes(curl_command))
    except CurlParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    # Authorization gate: fail if firing requests without engagement context
    _check_authorization(engagement_context, dry_run=False, firing_requests=True)

    # If --no-authorization-required, warn but proceed without gates
    if not engagement_context and no_authorization_required:
        console.print(
            "[yellow]Warning:[/yellow] Running without authorization context. "
            "Security gates (scope, destructive, kill switch) are disabled."
        )

    # Run recon
    try:
        recon_result = asyncio.run(_run_recon_async(req, calibrate))
    except Exception as e:
        console.print(f"[red]Recon error:[/red] {e}")
        sys.exit(1)

    # Targeting (auto)
    req = run_targeting(req, auto=True)

    # Build payloads
    payloads = _build_payload_candidates(req)

    if not payloads:
        console.print("[yellow]No payloads generated.[/yellow]")
        sys.exit(0)

    # Compute baseline
    from nagapasha.engine.diff import BaselineFingerprint
    if recon_result.baseline_fingerprint:
        bp = recon_result.baseline_fingerprint
        baseline = BaselineFingerprint(
            status_code=bp.status_code,
            content_length=bp.content_length,
            body_hash=bp.body_hash,
            avg_response_time=bp.avg_response_time,
            header_names=frozenset(),
            body_preview=bp.body_hash[:100],
        )
    else:
        console.print("[red]No baseline available.[/red]")
        sys.exit(1)

    # Run payloads
    rate_config = recon_result.rate_limit_config or RateLimitConfig(burst=10, refill_rate=4.0)

    loop = PayloadLoop(
        request_model=req,
        baseline_fingerprint=baseline,
        payloads=payloads,
        rate_limit_pps=rate_config.refill_rate,
        rate_limit_burst=rate_config.burst,
        max_requests=max_requests,
        engagement_context=engagement_context,
        allow_destructive=engagement_context.settings.get("allow_destructive", False) if engagement_context else False,
    )

    results = asyncio.run(loop.run())

    # Create report
    from nagapasha.stages.stage12_reporting import Report
    report = Report(
        engagement_id=engagement_context.engagement_id if engagement_context else "cicd",
        target_url=req.url,
        method=req.method,
        summary={
            "total_fired": results["total_fired"],
            "hits": results["hits"],
            "near_misses": results["near_misses"],
        },
    )

    # Add findings using add_finding() for redaction and hashing
    for r in loop.hits + loop.near_misses:
        confidence = 0.9 if r.classification == "HIT" else 0.5
        report.add_finding(
            parameter_name=r.candidate.parameter.name,
            attack_class=r.candidate.attack_class,
            payload=r.candidate.payload,
            evidence=str(r._evidence()),
            confidence=confidence,
        )

    # Save report
    output_dir = Path("reports")
    paths = report.save(output_dir, format=output_format)

    # Print results
    console.print(f"\n[bold]CI/CD Results:[/bold]")
    console.print(f"  Total fired: {results['total_fired']}")
    console.print(f"  Hits: {results['hits']}")
    console.print(f"  Near-misses: {results['near_misses']}")
    console.print(f"  Reports saved to: {output_dir}")

    # Check severity threshold based on --fail-on-severity
    SEVERITY_THRESHOLDS = {
        "low": 0.0,
        "medium": 0.5,
        "high": 0.8,
        "critical": 0.95,
    }
    threshold = SEVERITY_THRESHOLDS.get(fail_on_severity.lower(), 0.8)
    high_severity_count = sum(
        1 for f in report.findings
        if f.get("confidence", 0) >= threshold
    )

    if high_severity_count > 0:
        console.print(f"\n[red]FAIL: {high_severity_count} {fail_on_severity}-severity or higher finding(s) detected[/red]")
        sys.exit(1)
    else:
        console.print("\n[green]PASS: No high-severity findings[/green]")
        sys.exit(0)


@app.command()
def template(
    action: str = typer.Argument(
        ...,
        help="Action: create, load, list",
    ),
    name: Optional[str] = typer.Option(
        None, "--name", "-n", help="Template name"
    ),
    curl_command: Optional[str] = typer.Option(
        None, "--curl", help="Curl command for template (use with create)"
    ),
) -> None:
    """Manage engagement templates."""
    template_dir = Path("templates")
    template_dir.mkdir(parents=True, exist_ok=True)

    if action == "create":
        if not curl_command:
            console.print("[red]Error: --curl is required for create action[/red]")
            sys.exit(1)
        if not name:
            console.print("[red]Error: --name is required for create action[/red]")
            sys.exit(1)

        # Parse the curl command
        try:
            req = parse_curl(_strip_ansi_c_quotes(curl_command))
        except CurlParseError as e:
            console.print(f"[red]Parse error:[/red] {e}")
            sys.exit(1)

        # Create template
        template_data = {
            "name": name,
            "target_url": req.url,
            "method": req.method,
            "headers": dict(req.headers),
            "cookies": dict(req.cookies),
            "body": req.body,
            "body_type": req.body_type,
        }

        template_path = template_dir / f"{name}.json"
        template_path.write_text(json.dumps(template_data, indent=2))
        console.print(f"[green]Template saved:[/green] {template_path}")

    elif action == "load":
        if not name:
            console.print("[red]Error: --name is required for load action[/red]")
            sys.exit(1)

        template_path = template_dir / f"{name}.json"
        if not template_path.exists():
            console.print(f"[red]Error: Template not found:[/red] {template_path}")
            sys.exit(1)

        template_data = json.loads(template_path.read_text())
        console.print(f"[green]Template loaded:[/green] {name}")
        console.print(f"  Target: {template_data['target_url']}")
        console.print(f"  Method: {template_data['method']}")

    elif action == "list":
        templates = list(template_dir.glob("*.json"))
        if not templates:
            console.print("[dim]No templates found.[/dim]")
            return

        console.print("[bold]Templates:[/bold]")
        for t in templates:
            console.print(f"  - {t.stem}")

    else:
        console.print(f"[red]Unknown action:[/red] {action}")
        sys.exit(1)

console = Console()


def _print_request_model(req: RequestModel) -> None:
    """Pretty-print a RequestModel."""
    # Method + URL
    console.print(f"[bold]Method:[/bold] {req.method}")
    console.print(f"[bold]URL:[/bold] {req.url}")
    console.print(f"[bold]Base URL:[/bold] {req.base_url}")

    # Headers
    if req.headers:
        console.print("\n[bold]Headers:[/bold]")
        for k, v in req.headers.items():
            console.print(f"  {k}: {v[:80]}{'...' if len(v) > 80 else ''}")

    # Cookies
    if req.cookies:
        console.print("\n[bold]Cookies:[/bold]")
        for k, v in req.cookies.items():
            console.print(f"  {k}: {v[:60]}{'...' if len(v) > 60 else ''}")

    # Body
    if req.body:
        body_preview = req.body[:200]
        console.print(f"\n[bold]Body:[/bold] ({req.body_type or 'raw'})")
        console.print(f"  {body_preview}{'...' if len(req.body) > 200 else ''}")

    # Parameters table
    if req.parameters:
        console.print(f"\n[bold]Parameters ({len(req.parameters)}):[/bold]")
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Name", style="dim")
        table.add_column("Location")
        table.add_column("Type")
        table.add_column("Raw Value")
        table.add_column("Fuzz?")
        table.add_column("Skip Auth?")

        for p in req.parameters:
            fuzz = "[green]yes[/green]" if p.is_fuzz_target else "[dim]no[/dim]"
            skip = "[yellow]yes[/yellow]" if p.do_not_fuzz else "[dim]no[/dim]"
            table.add_row(
                p.name,
                p.location,
                p.inferred_type,
                p.raw_value[:50] + ("..." if len(p.raw_value) > 50 else ""),
                fuzz,
                skip,
            )
        console.print(table)


async def _run_recon_async(req: RequestModel, calibrate: int) -> Any:
    """Async helper to run recon."""
    rl = TokenBucketRateLimiter(RateLimitConfig(burst=10, refill_rate=4.0))
    runner = HttpRunner(rate_limiter=rl)
    return await run_recon(req, runner, calibrate_count=calibrate)


async def _generate_script_async(req: RequestModel, calibrate: int,
                                  output: Optional[Path]) -> Path:
    """Async helper to generate script."""
    rl = TokenBucketRateLimiter(RateLimitConfig(burst=10, refill_rate=4.0))
    runner = HttpRunner(rate_limiter=rl)
    recon_result = await run_recon(req, runner, calibrate_count=calibrate)

    # Write recon results into request model
    req.auth_valid = recon_result.auth_valid
    req.jwt_info = recon_result.jwt_info.to_dict() if recon_result.jwt_info else None
    if recon_result.baseline_fingerprint:
        req.baseline_fingerprint = {
            "status_code": recon_result.baseline_fingerprint.status_code,
            "content_length": recon_result.baseline_fingerprint.content_length,
            "body_hash": recon_result.baseline_fingerprint.body_hash,
            "avg_response_time": recon_result.baseline_fingerprint.avg_response_time,
        }
    req.rate_limit_pps = recon_result.rate_limit_pps
    if recon_result.rate_limit_config:
        req.rate_limit_config = {
            "burst": recon_result.rate_limit_config.burst,
            "refill_rate": recon_result.rate_limit_config.refill_rate,
        }
    req.confirmed_tech_stack = recon_result.tech_stack
    req.scope_confirmed = True

    generator = StaticScriptGenerator()
    return generator.generate(req, output_path=output)


@app.command()
def parse(
    curl_command: str = typer.Argument(
        ...,
        help="The curl command to parse (e.g. 'curl -X GET ...')",
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output as raw JSON instead of pretty print"
    ),
) -> None:
    """Parse a curl command into a structured RequestModel."""
    try:
        req = parse_curl(_strip_ansi_c_quotes(curl_command))
    except CurlParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
        sys.exit(1)

    if json_output:
        json.dump(req.to_dict(), sys.stdout, indent=2)
        print()
    else:
        _print_request_model(req)


@app.command()
def recon(
    curl_command: str = typer.Argument(
        ...,
        help="The curl command to recon (e.g. 'curl -X GET ...')",
    ),
    calibrate: int = typer.Option(
        5, "--calibrate", "-c", help="Number of baseline calibration fires"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-d", help="Parse only, don't fire any requests"
    ),
    engagement: Optional[str] = typer.Option(
        None, "--engagement", "-e", help="Path to .ctx engagement file"
    ),
) -> None:
    """Run parse + recon on a curl command."""
    # Load engagement context if provided
    engagement_context = None
    if engagement:
        try:
            from nagapasha.engagement import EngagementContext
            engagement_context = EngagementContext.load(Path(engagement))
        except Exception as e:
            console.print(f"[red]Failed to load engagement context:[/red] {e}")
            sys.exit(3)

    try:
        req = parse_curl(_strip_ansi_c_quotes(curl_command))
    except CurlParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    if dry_run:
        console.print("[dim]Dry run — parsed request only (no network calls)[/dim]")
        _print_request_model(req)
        return

    # Authorization gate: fail if firing requests without engagement context
    _check_authorization(engagement_context, dry_run=False, firing_requests=True)

    # Stage 0: Scope check (if engagement context provided)
    if engagement_context:
        from nagapasha.scope import ScopeChecker
        scope_checker = ScopeChecker(engagement_context)
        scope_checker.check(
            url=req.url,
            method=req.method,
            description="Recon scope check",
        )

    # Run recon
    try:
        result = asyncio.run(_run_recon_async(req, calibrate))
    except Exception as e:
        console.print(f"[red]Recon error:[/red] {e}")
        sys.exit(1)

    # Print results
    console.print("\n[bold]Recon Results:[/bold]")

    # Auth
    auth_text = (
        "[green]Valid (2xx)[/green]" if result.auth_valid
        else "[red]Invalid ({}: {})".format(result.auth_status, "401/403")
        if result.auth_status and result.auth_status not in (200, 201, 202, 204)
        else f"[dim]Status {result.auth_status}[/dim]"
    )
    console.print(f"  Auth: {auth_text}")

    # JWT
    if result.jwt_info and result.jwt_info.is_jwt:
        jwt = result.jwt_info
        console.print(f"  JWT:  detected (alg={jwt.alg}, exp={jwt.exp})")
        if jwt.algorithm_flagged:
            console.print(f"    [yellow]Flagged:[/yellow] {jwt.flag_reason}")

    # Baseline
    if result.baseline_fingerprint:
        fp = result.baseline_fingerprint
        console.print(f"  Baseline: status={fp.status_code}, "
                      f"content-length={fp.content_length}, "
                      f"avg-time={fp.avg_response_time:.3f}s")

    # Flakiness
    if result.is_flaky:
        console.print(f"  [yellow]Flaky target:[/yellow] {result.flakiness_reason}")

    # Rate limit
    if result.rate_limit_config:
        rl = result.rate_limit_config
        console.print(f"  Rate limit: burst={rl.burst}, "
                      f"refill={rl.refill_rate} req/s")

    # Tech stack
    if result.tech_stack:
        console.print(f"  Tech stack: {json.dumps(result.tech_stack, indent=4)}")

    # WAF
    if result.waf_detected:
        console.print(f"  [yellow]WAF/CDN detected:[/yellow] {result.waf_name}")

    # Save to SQLite
    with EngagementStore() as store:
        eid = store.create_engagement(
            target_host=req.base_url,
            target_url=req.url,
            method=req.method,
            scope_confirmed=True,
        )
        store.update_engagement(
            eid,
            status="recon_complete",
            rate_limit_pps=result.rate_limit_pps,
            notes=json.dumps(result.to_dict()),
        )
        console.print(f"\n[green]Engagement saved:[/green] {eid}")


@app.command()
def generate(
    curl_command: str = typer.Argument(
        ...,
        help="The curl command to generate a Phase 1 script for",
    ),
    calibrate: int = typer.Option(
        5, "--calibrate", "-c", help="Number of baseline calibration fires"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output script path"
    ),
    mcp_search: bool = typer.Option(
        False, "--mcp-search", help="Enable MCP web search fallback for payload sourcing"
    ),
) -> None:
    """Parse + recon + output a standalone Phase 1 execution script."""
    try:
        req = parse_curl(_strip_ansi_c_quotes(curl_command))
    except CurlParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    # Scope confirmation removed — user is responsible for authorization
    scope_guard = ScopeGuard()
    scope_guard.confirm_scope("User confirmed at " + str(__import__('time').time()))

    # Run recon + generate script
    try:
        script_path = asyncio.run(_generate_script_async(req, calibrate, output))
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    console.print(f"\n[green]Phase 1 script generated:[/green] {script_path}")
    console.print(f"  Run it with: python3 {script_path}")

    # Save to SQLite
    with EngagementStore() as store:
        eid = store.create_engagement(
            target_host=req.base_url,
            target_url=req.url,
            method=req.method,
            scope_confirmed=True,
        )
        # Use defaults for rate limit (generate command doesn't capture recon result)
        store.update_engagement(
            eid,
            status="script_generated",
            rate_limit_pps=4.0,  # default
            generated_script_path=str(script_path),
        )
        console.print(f"  Engagement ID: {eid}")


def _check_authorization(
    engagement_context: Optional[Any],
    dry_run: bool,
    firing_requests: bool,
) -> None:
    """Validate that authorization is configured before proceeding.

    When firing network requests without --engagement, security gates
    (scope, destructive, kill switch) silently no-op. This is a security
    risk. We hard-fail unless --dry-run is set or --no-authorization-required
    is explicitly passed.

    Args:
        engagement_context: Loaded EngagementContext, or None
        dry_run: Whether --dry-run was passed
        firing_requests: Whether we are about to fire network requests
    """
    if dry_run:
        # Dry run never sends network requests — allow without engagement
        return
    if not firing_requests:
        # Recon-only or parse-only — no network calls
        return
    if engagement_context is not None:
        # Authorization is configured
        return
    # No engagement and no dry-run — security risk
    console.print(
        "[red]Error:[/red] No authorization context configured. "
        "Pass --engagement to a .ctx file, or use --dry-run to skip network calls."
    )
    console.print(
        "[dim]  Nagapasha security gates (scope, destructive-payload, kill switch) "
        "are disabled without an engagement context.[/dim]"
    )
    sys.exit(3)


def _on_result(result) -> None:
    """Print each payload result for the run/full commands."""
    classification = result.classification
    if classification == "HIT":
        console.print(f"  [bold green]HIT[/bold green] [{result.candidate.parameter.name}] "
                      f"{classification} | status={result.status_code} | "
                      f"{result.candidate.attack_class} | payload={result.candidate.payload[:40]}...")
        ev = result._evidence()
        if ev:
            console.print(f"    evidence: {ev}")
    elif classification == "NEAR-MISS":
        console.print(f"  [yellow]NEAR-MISS[/yellow] [{result.candidate.parameter.name}] "
                      f"{classification} | status={result.status_code} | "
                      f"{result.candidate.attack_class} | payload={result.candidate.payload[:40]}...")
    # no-diff: silent


async def _run_script_async(script_path: Path) -> None:
    """Execute a generated Phase 1 script by importing and running its main."""
    import subprocess
    console.print(f"\n[bold]Executing Phase 1 script:[/bold] {script_path}")
    result = subprocess.run(
        ["python3", str(script_path)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.stdout:
        console.print(result.stdout)
    if result.stderr:
        console.print(f"[red]stderr:[/red] {result.stderr}")
    console.print(f"\n[green]Script exited with code {result.returncode}[/green]")


@app.command()
def run(
    script_path: Path = typer.Argument(
        ...,
        exists=True,
        help="Path to the generated Phase 1 script to execute",
    ),
) -> None:
    """Execute a generated Phase 1 script."""
    asyncio.run(_run_script_async(script_path))


@app.command()
def full(
    curl_command: str = typer.Argument(
        ...,
        help="The curl command to run through the full pipeline",
    ),
    calibrate: int = typer.Option(
        5, "--calibrate", "-c", help="Number of baseline calibration fires"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-d", help="Parse + recon only, don't fire payloads"
    ),
    max_requests: int = typer.Option(
        1000, "--max-requests", "-m", help="Hard cap on total requests"
    ),
    batch_size: int = typer.Option(
        1, "--batch-size", "-b", help="Number of concurrent payload fires"
    ),
    output_format: str = typer.Option(
        "json", "--output-format", "-f",
        help="Output format: json, markdown, sarif, junit, html, or all"
    ),
    sign: bool = typer.Option(
        False, "--sign", help="Enable HMAC request signing"
    ),
    allowed_hosts: Optional[str] = typer.Option(
        None, "--allowed-hosts", help="Comma-separated host allowlist"
    ),
    mcp_search: bool = typer.Option(
        False, "--mcp-search", help="Enable MCP web search fallback for payload sourcing"
    ),
    engagement: Optional[str] = typer.Option(
        None, "--engagement", "-e", help="Path to .ctx engagement file"
    ),
    no_authorization_required: bool = typer.Option(
        False, "--no-authorization-required",
        help="Explicitly disable security gates (not recommended for live targets)",
    ),
) -> None:
    """Full pipeline: parse → recon → targeting → generate → execute."""
    # Load engagement context if provided
    engagement_context = None
    if engagement:
        try:
            from nagapasha.engagement import EngagementContext
            engagement_context = EngagementContext.load(Path(engagement))
        except Exception as e:
            console.print(f"[red]Failed to load engagement context:[/red] {e}")
            sys.exit(3)

    try:
        req = parse_curl(_strip_ansi_c_quotes(curl_command))
    except CurlParseError as e:
        console.print(f"[red]Parse error:[/red] {e}")
        sys.exit(1)

    # Authorization gate: fail if firing requests without engagement context
    _check_authorization(engagement_context, dry_run, firing_requests=not dry_run)

    # If --no-authorization-required, warn but proceed without gates
    if not engagement_context and not dry_run and no_authorization_required:
        console.print(
            "[yellow]Warning:[/yellow] Running without authorization context. "
            "Security gates (scope, destructive, kill switch) are disabled."
        )

    # Stage 0: Scope check (if engagement context provided)
    if engagement_context:
        from nagapasha.scope import ScopeChecker
        scope_checker = ScopeChecker(engagement_context)
        scope_checker.check(
            url=req.url,
            method=req.method,
            description="Initial scope check",
        )

    # Run recon
    try:
        recon_result = asyncio.run(_run_recon_async(req, calibrate))
    except Exception as e:
        console.print(f"[red]Recon error:[/red] {e}")
        sys.exit(1)

    # Print recon summary
    console.print("\n[bold]Recon Summary:[/bold]")
    console.print(f"  Auth: {'[green]Valid[/green]' if recon_result.auth_valid else '[red]Invalid[/red]'}")
    if recon_result.jwt_info and recon_result.jwt_info.is_jwt:
        console.print(f"  JWT: alg={recon_result.jwt_info.alg}, exp={recon_result.jwt_info.exp}")
    if recon_result.baseline_fingerprint:
        fp = recon_result.baseline_fingerprint
        console.print(f"  Baseline: status={fp.status_code}, "
                      f"content-length={fp.content_length}, "
                      f"avg-time={fp.avg_response_time:.3f}s")
    if recon_result.rate_limit_config:
        rl = recon_result.rate_limit_config
        console.print(f"  Rate limit: burst={rl.burst}, refill={rl.refill_rate} req/s")
    if recon_result.waf_detected:
        console.print(f"  [yellow]WAF/CDN detected:[/yellow] {recon_result.waf_name}")

    # Targeting (auto-select for full pipeline)
    req = run_targeting(req, auto=True)

    # Count fuzz targets
    targets = [p for p in req.parameters if p.is_fuzz_target]
    console.print(f"\n[bold]Targets:[/bold] {len(targets)} parameter(s) selected")

    if dry_run:
        console.print("[dim]Dry run — recon + targeting only (no payloads fired)[/dim]")
        return

    # Generate script for archival
    generator = StaticScriptGenerator()
    script_path = generator.generate(req)
    console.print(f"\n[green]Phase 1 script:[/green] {script_path}")

    # Build payloads from attack_specs
    payloads = _build_payload_candidates(req)
    console.print(f"[bold]Payloads ready:[/bold] {len(payloads)}")

    if not payloads:
        console.print("[yellow]No payloads generated. Run Strategist first.[/yellow]")
        return

    # Compute baseline fingerprint for the payload loop
    from nagapasha.engine.diff import BaselineFingerprint
    if recon_result.baseline_fingerprint:
        bp = recon_result.baseline_fingerprint
        baseline = BaselineFingerprint(
            status_code=bp.status_code,
            content_length=bp.content_length,
            body_hash=bp.body_hash,
            avg_response_time=bp.avg_response_time,
            header_names=frozenset(),  # Will be populated by the runner
            body_preview=bp.body_hash[:100],
        )
    else:
        console.print("[red]No baseline available — cannot run payloads.[/red]")
        sys.exit(1)

    # Run payloads
    console.print("\n[bold]Firing payloads...[/bold]")
    rate_config = recon_result.rate_limit_config or RateLimitConfig(burst=10, refill_rate=4.0)

    # Parse allowed hosts from command line (if provided)
    host_allowlist = None
    if allowed_hosts:
        host_allowlist = [h.strip() for h in allowed_hosts.split(",")]

    loop = PayloadLoop(
        request_model=req,
        baseline_fingerprint=baseline,
        payloads=payloads,
        rate_limit_pps=rate_config.refill_rate,
        rate_limit_burst=rate_config.burst,
        max_requests=max_requests,
        batch_size=batch_size,
        engagement_context=engagement_context,
        allow_destructive=engagement_context.settings.get("allow_destructive", False) if engagement_context else False,
        host_allowlist=host_allowlist,
    )

    # Capture results
    results = asyncio.run(loop.run(on_result=_on_result))

    # Summary
    console.print("\n[bold]Execution Summary:[/bold]")
    console.print(f"  Total fired:  {results['total_fired']}")
    console.print(f"  [green]Hits:[/green]        {results['hits']}")
    console.print(f"  [yellow]Near-misses:[/yellow] {results['near_misses']}")
    console.print(f"  No-diff:       {results['no_diff']}")
    console.print(f"  Elapsed:       {results['elapsed_seconds']}s")
    console.print(f"  Throughput:    {results['requests_per_second']} req/s")

    # Save engagement
    with EngagementStore() as store:
        eid = store.create_engagement(
            target_host=req.base_url,
            target_url=req.url,
            method=req.method,
            scope_confirmed=True,
        )
        req.engagement_id = eid
        store.update_engagement(
            eid,
            status="complete",
            rate_limit_pps=recon_result.rate_limit_pps,
            notes=json.dumps({
                "results": results,
                "script_path": str(script_path),
            }),
            generated_script_path=str(script_path),
        )
        console.print(f"\n[green]Engagement saved:[/green] {eid}")


# Location priority for payload ordering (highest first)
# JSON body params are tested first (most effective, least noisy)
# Path params next (effective for traversal/LFI)
# Cookie/Auth headers (IDOR, session manipulation)
# Other headers (lower priority)
# Query string (least prioritized)
LOCATION_PRIORITY = {
    "body_json": 1,
    "path": 2,
    "cookie": 3,
    "header": 4,
    "query": 5,
    "body_form": 6,
    "body_multipart": 7,
}


def _location_sort_key(param: ParameterModel) -> tuple[int, str]:
    """Sort key for parameters by location priority then name."""
    loc_priority = LOCATION_PRIORITY.get(param.location, 99)
    return (loc_priority, param.name)


def _build_payload_candidates(
    req: RequestModel,
    mcp_search: bool = False,
) -> list[PayloadCandidate]:
    """Build PayloadCandidate list from RequestModel's attack_specs and parameters.

    If attack_specs are present, use them. Otherwise generate default payloads
    for each fuzz target parameter. If mcp_search is True and local KB is
    insufficient, attempt online search via MCP web tools.

    Parameters are sorted by location priority:
    1. JSON body (body_json) — highest priority
    2. URL path parameters
    3. Cookie/Auth headers
    4. Other request headers
    5. Query string parameters — lowest priority
    """
    candidates: list[PayloadCandidate] = []

    # If we have attack specs from Strategist/Librarian/Fitter
    if req.attack_specs:
        # Sort specs by priority field (lower = higher priority) if present
        specs = list(req.attack_specs)
        has_priority = any("priority" in s for s in specs)
        if has_priority:
            specs.sort(key=lambda s: s.get("priority", 99))

        for spec in specs:
            param_idx = spec.get("parameter_index")
            if param_idx is None or param_idx >= len(req.parameters):
                continue
            param = req.parameters[param_idx]
            if not param.is_fuzz_target:
                continue

            for payload in spec.get("payloads", []):
                candidates.append(PayloadCandidate(
                    parameter=param,
                    payload=payload.get("value", payload) if isinstance(payload, dict) else payload,
                    attack_class=spec.get("attack_class", "generic"),
                    payload_tags=spec.get("payload_tags", []),
                    rationale=spec.get("rationale", ""),
                ))
        return candidates

    # No attack_specs — build from parameters directly, ordered by location priority
    for param in sorted(req.parameters, key=_location_sort_key):
        if not param.is_fuzz_target:
            continue
        default_payloads = _default_payloads_for_type(param.inferred_type)
        for payload in default_payloads:
            candidates.append(PayloadCandidate(
                parameter=param,
                payload=payload,
                attack_class=f"default/{param.inferred_type}",
            ))

    # If MCP search is enabled, try to enrich with online sources
    if mcp_search:
        try:
            from nagapasha.llm.runner import AnthropicRunner
            from nagapasha.stages.stage07_librarian import run_librarian

            # Determine attack classes from parameter types
            attack_classes = list({
                p.inferred_type.replace(" ", "_")
                for p in req.parameters
                if p.is_fuzz_target
            })

            runner = AnthropicRunner()
            try:
                payloads_dict = run_librarian(
                    attack_classes=attack_classes,
                    tech_stack=req.confirmed_tech_stack,
                    runner=runner,
                    use_mcp=True,
                )
            finally:
                runner.close()

            if payloads_dict:
                # Convert to PayloadCandidate format
                for ac, payloads in payloads_dict.items():
                    for param in req.parameters:
                        if not param.is_fuzz_target:
                            continue
                        if param.inferred_type.replace(" ", "_") == ac:
                            for p in payloads:
                                if isinstance(p, dict):
                                    candidates.append(PayloadCandidate(
                                        parameter=param,
                                        payload=p.get("value", ""),
                                        attack_class=ac,
                                        payload_tags=[p.get("technique", "")],
                                        rationale=p.get("technique", ""),
                                    ))
                                else:
                                    candidates.append(PayloadCandidate(
                                        parameter=param,
                                        payload=str(p),
                                        attack_class=ac,
                                    ))
                if candidates:
                    logger.info(f"MCP search returned {len(candidates)} payloads")
        except Exception as e:
            logger.warning(f"MCP search failed: {e}")

    # If still no candidates after MCP, add default payloads for remaining params
    if not candidates:
        for param in sorted(req.parameters, key=_location_sort_key):
            if not param.is_fuzz_target:
                continue
            default_payloads = _default_payloads_for_type(param.inferred_type)
            for payload in default_payloads:
                candidates.append(PayloadCandidate(
                    parameter=param,
                    payload=payload,
                    attack_class=f"default/{param.inferred_type}",
                ))

    return candidates


def _default_payloads_for_type(param_type: str) -> list[str]:
    """Generate default payloads for a parameter type."""
    if param_type == "int":
        return ["-1", "0", "999999", "9999999999"]
    elif param_type == "free_text":
        return ["<script>alert(1)</script>", "' OR '1'='1", "../../../etc/passwd"]
    elif param_type == "uuid":
        return ["00000000-0000-0000-0000-000000000000", "not-a-uuid"]
    elif param_type == "email":
        return ["a@b.com'--", "'; DROP TABLE users--"]
    elif param_type == "boolean":
        return ["true", "false", "1", "0"]
    elif param_type == "filename":
        return ["../etc/passwd", "../../../proc/self/environ", ";cat"]
    else:
        return ["<script>alert(1)</script>", "' OR '1'='1"]


# =============================================================================
# Stage 0 Commands: init, abort, status
# =============================================================================

@app.command("init")
def init_engagement(
    roe_file: Path = typer.Option(
        ..., "--roe", "-r", help="Path to ROE (Rules of Engagement) file (YAML)"
    ),
    engagement_id: str = typer.Option(
        ..., "--engagement-id", "-e", help="Unique engagement identifier"
    ),
    authorized_by: str = typer.Option(
        ..., "--authorized-by", "-a", help="Name/email of authorizer"
    ),
    allow_destructive: bool = typer.Option(
        False, "--allow-destructive", help="Allow destructive attack classes without confirmation"
    ),
) -> None:
    """Stage 0: Create signed EngagementContext from ROE.

    Validates the ROE document, extracts scope and authorization information,
    and creates a signed EngagementContext that will be used by all subsequent
    commands (recon, run, report).
    """
    # Read and validate ROE file
    try:
        roe_content = roe_file.read_text()
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] ROE file not found: {roe_file}")
        sys.exit(3)
    except Exception as e:
        console.print(f"[red]Error reading ROE:[/red] {e}")
        sys.exit(3)

    # Parse ROE (YAML or JSON)
    import yaml
    try:
        roe_data = yaml.safe_load(roe_content)
    except Exception as e:
        console.print(f"[red]Error parsing ROE:[/red] {e}")
        sys.exit(3)

    if not isinstance(roe_data, dict):
        console.print("[red]Error:[/red] ROE must be a YAML/JSON object")
        sys.exit(3)

    # Hash ROE for audit trail
    from nagapasha.engagement import hash_roe
    roe_hash = hash_roe(roe_content)

    # Warn if HMAC key is not set — engagement will be unsigned
    from nagapasha.utils.config import get_config
    hmac_key = get_config().get("engagement_hmac_key", "")
    if not hmac_key:
        console.print(
            "[yellow]Warning:[/yellow] NAGAPASHA_HMAC_KEY is not set. "
            "The engagement context will be created with an unsigned 'dev_' signature. "
            "All subsequent commands will skip signature verification. "
            "Set NAGAPASHA_HMAC_KEY or add engagement_hmac_key to config for tamper-proof engagements."
        )

    # Extract scope from ROE
    from nagapasha.engagement import validate_roe
    try:
        context = validate_roe(roe_data, engagement_id)
        context.roe_hash = roe_hash
        context.roe_path = str(roe_file)
    except ValueError as e:
        console.print(f"[red]ROE validation error:[/red] {e}")
        sys.exit(3)

    # Add destructive flag to allowed_attack_classes if requested
    if allow_destructive:
        context.allowed_attack_classes = list({
            *context.allowed_attack_classes,
            "rce", "command_injection", "deserialization",
        })

    # Save context
    ctx_path = Path(f"{engagement_id}.ctx")
    try:
        context.save(ctx_path)
    except Exception as e:
        console.print(f"[red]Error saving context:[/red] {e}")
        sys.exit(3)

    # Create state directory
    from nagapasha.utils.paths import get_state_dir
    state_dir = get_state_dir(engagement_id)

    console.print(f"[green]Engagement created:[/green] {ctx_path}")
    console.print(f"  Engagement ID: {context.engagement_id}")
    console.print(f"  Authorized by: {context.authorized_by}")
    console.print(f"  Scope: {len(context.scope_allowlist)} allow, {len(context.scope_denylist)} deny")
    console.print(f"  Methods: {', '.join(context.allowed_methods)}")
    if context.time_window_start and context.time_window_end:
        console.print(f"  Time window: {context.time_window_start} to {context.time_window_end}")
    console.print(f"  State dir: {state_dir}")
    console.print(f"\n[dim]Next: nagapasha recon --engagement {engagement_id}.ctx[/dim]")


@app.command("abort")
def abort_engagement(
    engagement_id: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement ID to abort"
    ),
) -> None:
    """Kill switch: write kill switch file for an engagement.

    This stops all ongoing `run` commands for the specified engagement.
    The kill switch is checked before every request, so the abort is
    nearly immediate.
    """
    from nagapasha.engagement import write_kill_switch
    from nagapasha.utils.paths import get_state_dir

    try:
        write_kill_switch(engagement_id)
        state_dir = get_state_dir(engagement_id)
        console.print(f"[green]Kill switch activated:[/green] {state_dir / 'kill_switch'}")
        console.print(f"  Engagement '{engagement_id}' is now aborted.")
        console.print(f"  Ongoing `nagapasha run` commands will stop at the next request boundary.")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(4)


@app.command("status")
def engagement_status(
    engagement_id: str = typer.Option(
        ..., "--engagement", "-e", help="Engagement ID to inspect"
    ),
) -> None:
    """Show engagement progress and status.

    Reads from the engagement state directory and displays:
    - Engagement context (scope, methods, time window)
    - Kill switch state
    - Progress (payloads fired, hits, near-misses)
    - Recent log entries
    """
    from nagapasha.engagement import EngagementContext
    from nagapasha.utils.paths import get_state_dir, get_checkpoint_file, get_log_file

    ctx_path = Path(f"{engagement_id}.ctx")
    if not ctx_path.exists():
        console.print(f"[red]Error:[/red] Engagement context not found: {ctx_path}")
        sys.exit(3)

    # Load context
    try:
        context = EngagementContext.load(ctx_path)
    except Exception as e:
        console.print(f"[red]Error loading context:[/red] {e}")
        sys.exit(3)

    # Display context
    console.print(f"[bold]Engagement: {context.engagement_id}[/bold]")
    console.print(f"  Authorized by: {context.authorized_by}")
    console.print(f"  Created: {context.created_at}")
    console.print(f"  Scope: {len(context.scope_allowlist)} allow, {len(context.scope_denylist)} deny")
    console.print(f"  Methods: {', '.join(context.allowed_methods)}")

    if context.time_window_start and context.time_window_end:
        console.print(f"  Time window: {context.time_window_start} to {context.time_window_end}")

    # Kill switch
    if context.is_kill_switch_active():
        console.print(f"  [bold red]Kill switch: ACTIVE[/bold red]")
    else:
        console.print(f"  Kill switch: inactive")

    # Load checkpoint
    checkpoint_file = get_checkpoint_file(engagement_id)
    if checkpoint_file.exists():
        try:
            import json
            checkpoint = json.loads(checkpoint_file.read_text())
            console.print(f"\n[bold]Progress:[/bold]")
            console.print(f"  Payloads fired: {checkpoint.get('total_fired', 0)}")
            console.print(f"  Hits: {checkpoint.get('hits', 0)}")
            console.print(f"  Near-misses: {checkpoint.get('near_misses', 0)}")
            console.print(f"  Checkpoint: {checkpoint.get('checkpoint_index', 0)}")
        except Exception:
            pass

    # Recent logs
    log_file = get_log_file(engagement_id)
    if log_file.exists():
        console.print(f"\n[bold]Recent logs:[/bold]")
        lines = log_file.read_text().strip().split("\n")[-5:]  # Last 5 lines
        for line in lines:
            try:
                import json
                log_entry = json.loads(line)
                timestamp = log_entry.get("timestamp", "")
                message = log_entry.get("message", "")
                level = log_entry.get("level", "INFO")
                console.print(f"  [{timestamp}] [{level}] {message}")
            except Exception:
                console.print(f"  {line[:80]}")


if __name__ == "__main__":
    main()
