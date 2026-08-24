"""Payload execution loop for Phase 1.

Drives sequential/batched payload firing against a target, classifying each
response as HIT / NEAR-MISS / no-diff with evidence capture.

Designed to be embedded in standalone scripts AND used directly by the CLI
`nagapasha run` command.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from nagapasha.engine.diff import (
    BaselineFingerprint,
    compute_delta,
)
from nagapasha.engine.rate_limiter import (
    RateLimitConfig,
    TokenBucketRateLimiter,
)
from nagapasha.engine.runner import HttpRunner
from nagapasha.models.request_model import ParameterModel, RequestModel
from nagapasha.engagement import EngagementContext
from nagapasha.scope import ScopeError

import logging
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class PayloadCandidate:
    """A single payload to fire against a parameter.

    Attributes:
        parameter: Parameter model for the target parameter
        payload: The payload value to inject
        attack_class: The attack class (e.g., "sql_injection", "rce")
        payload_tags: Optional tags for payload categorization
        rationale: Why this payload was selected
        destructive: True if this payload could cause data loss or system damage
        probe_variant: Optional constrained probe variant (e.g., sleep(5) before RCE)
        identity_hash: Stable hash for dedup and idempotent resume
    """

    parameter: ParameterModel
    payload: str
    attack_class: str
    payload_tags: list[str] = field(default_factory=list)
    rationale: str = ""
    destructive: bool = False
    probe_variant: Optional["PayloadCandidate"] = None
    identity_hash: str = ""  # SHA256 of (param.name, param.location, attack_class, payload)

    def __post_init__(self) -> None:
        """Auto-compute identity_hash if not provided."""
        if not self.identity_hash:
            self.identity_hash = compute_identity_hash(
                self.parameter.name,
                self.parameter.location,
                self.attack_class,
                self.payload,
            )


def compute_identity_hash(
    param_name: str,
    param_location: str,
    attack_class: str,
    payload: str,
) -> str:
    """Compute stable identity hash for a payload candidate.

    Args:
        param_name: Parameter name
        param_location: Parameter location (query, body, etc.)
        attack_class: Attack class
        payload: Payload value

    Returns:
        SHA256 hex digest
    """
    import hashlib

    hash_input = f"{param_name}|{param_location}|{attack_class}|{payload}"
    return hashlib.sha256(hash_input.encode()).hexdigest()


@dataclass
class PayloadResult:
    """Result of firing a single payload."""

    candidate: PayloadCandidate
    status_code: int
    delta: Any  # ResponseDelta
    elapsed: float
    response_body_preview: str = ""
    hit: bool = False
    near_miss: bool = False

    @property
    def classification(self) -> str:
        """HIT | NEAR-MISS | no-diff.

        Derives from the ``hit``/``near_miss`` attributes, falling back to the
        delta flags if those aren't explicitly set (i.e. both are still at their
        defaults of False).
        """
        # Explicit flags win if set
        if self.hit:
            return "HIT"
        if self.near_miss:
            return "NEAR-MISS"
        # Otherwise infer from the delta
        if self.delta is not None:
            if self.delta.is_confirmed_hit:
                return "HIT"
            if self.delta.is_near_miss:
                return "NEAR-MISS"
        return "no-diff"

    def to_dict(self) -> dict[str, Any]:
        return {
            "parameter": self.candidate.parameter.name,
            "location": self.candidate.parameter.location,
            "attack_class": self.candidate.attack_class,
            "payload": self.candidate.payload[:200],
            "classification": self.classification,
            "status_code": self.status_code,
            "elapsed": self.elapsed,
            "hit": self.hit,
            "near_miss": self.near_miss,
            "delta": self.delta.to_dict() if self.delta else {},
            "evidence": self._evidence(),
        }

    def _evidence(self) -> dict[str, str]:
        """Capture key evidence for HITs/Near-misses."""
        ev: dict[str, str] = {}
        if self.delta is None:
            return ev
        if self.delta.has_error_signature:
            ev["error_signature"] = self.delta.error_signature
        if self.delta.has_reflected_payload:
            ev["reflected_text"] = self.delta.reflected_text
        if self.delta.status_delta is not None:
            ev["status_delta"] = f"{self.delta.status_delta:+d}"
        if self.delta.content_length_delta:
            ev["content_length_delta"] = str(self.delta.content_length_delta)
        if self.delta.delta_details:
            ev["details"] = "; ".join(self.delta.delta_details[:5])
        return ev


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------

ResultCallback = Callable[[PayloadResult], None]


# ---------------------------------------------------------------------------
# PayloadLoop
# ---------------------------------------------------------------------------

class PayloadLoop:
    """Drives the sequential/batched payload firing loop.

    Usage:
        loop = PayloadLoop(
            request_model=original_req,
            baseline_fingerprint=baseline,
            payloads=[candidate1, candidate2, ...],
            rate_limit_pps=4.0,
            rate_limit_burst=10,
            max_requests=1000,
        )
        loop.run(on_result=print_result)
    """

    def __init__(
        self,
        request_model: RequestModel,
        baseline_fingerprint: BaselineFingerprint,
        payloads: list[PayloadCandidate],
        rate_limit_pps: float = 4.0,
        rate_limit_burst: float = 10.0,
        max_requests: int = 1000,
        batch_size: int = 1,
        jwt_deadline: Optional[float] = None,
        engagement_context: Optional[EngagementContext] = None,
        allow_destructive: bool = False,
        host_allowlist: Optional[list[str]] = None,
    ) -> None:
        self.request_model = request_model
        self.baseline = baseline_fingerprint
        self.payloads = payloads
        self.max_requests = max_requests
        self.batch_size = batch_size

        # Rate limiter
        config = RateLimitConfig(
            burst=rate_limit_burst,
            refill_rate=rate_limit_pps,
        )
        self.rate_limiter = TokenBucketRateLimiter(config)

        # Stage 2.5: Exfiltration prevention
        self.host_allowlist = host_allowlist

        self.runner = HttpRunner(
            rate_limiter=self.rate_limiter,
            host_allowlist=self.host_allowlist,
        )

        # JWT deadline (seconds before expiry to stop)
        self.jwt_deadline = jwt_deadline

        # Stage 0: Scope enforcement
        self.engagement_context = engagement_context
        self.scope_checker = None
        if engagement_context:
            from nagapasha.scope import ScopeChecker
            self.scope_checker = ScopeChecker(engagement_context)

        # Stage 8.5: Destructive payload gate
        self.allow_destructive = allow_destructive

        # Kill switch
        self._kill: asyncio.Event = asyncio.Event()
        self._kill.clear()

        # Pause/resume
        self._paused: bool = False
        self._resume_event: asyncio.Event = asyncio.Event()
        self._resume_event.set()  # not paused initially
        self._paused_idx: int = 0  # index where we paused (for resume)

        # Stats
        self.total_fired: int = 0
        self.hits: list[PayloadResult] = []
        self.near_misses: list[PayloadResult] = []
        self.no_diff_count: int = 0
        self._request_count: int = 0
        self._start_time: float = time.monotonic()

        # Stage 9.5: Continuous recalibration
        from nagapasha.engine.recalibration import RecalibrationChecker
        self.recalibration = RecalibrationChecker(
            rate_limit_pps=rate_limit_pps,
            max_requests=max_requests,
        )
        self._baseline_fingerprint_dict = self._to_dict(baseline_fingerprint)

        # Stage 88: Dedup & idempotent resume
        self._fired_identities: set[str] = set()

    def kill(self) -> None:
        """Signal the loop to stop as soon as it can."""
        self._kill.set()

    def pause(self) -> bool:
        """Pause the loop. Returns True if successfully paused."""
        if self._paused:
            return False
        self._paused = True
        self._resume_event.clear()
        self._paused_idx = self._request_count
        return True

    def resume(self) -> bool:
        """Resume a paused loop. Returns True if successfully resumed."""
        if not self._paused:
            return False
        self._paused = False
        self._resume_event.set()
        return True

    def kill_and_reset(self) -> None:
        """Kill the loop and reset pause state for future runs."""
        self._kill.set()
        self._paused = False
        self._resume_event.set()

    def save_checkpoint(self, checkpoint_path: str) -> None:
        """Save execution checkpoint to file.

        Saves the current index, payloads, and stats so execution can be resumed later.
        """
        import json
        # Serialize payloads for checkpoint
        payload_data = [
            {
                "parameter_name": p.parameter.name,
                "parameter_location": p.parameter.location,
                "payload": p.payload,
                "attack_class": p.attack_class,
            }
            for p in self.payloads
        ]
        checkpoint = {
            "total_fired": self.total_fired,
            "hits": len(self.hits),
            "near_misses": len(self.near_misses),
            "no_diff": self.no_diff_count,
            "request_count": self._request_count,
            "paused": self._paused,
            "killed": self._kill.is_set(),
            "payloads": payload_data,
            "fired_identities": list(self._fired_identities),
        }
        with open(checkpoint_path, 'w') as f:
            json.dump(checkpoint, f, indent=2)

    def load_checkpoint(self, checkpoint_path: str) -> dict:
        """Load execution checkpoint from file.

        Returns:
            Checkpoint dict with total_fired, hits, near_misses, no_diff, etc.
        """
        import json
        with open(checkpoint_path, 'r') as f:
            checkpoint = json.load(f)
        # Update internal stats
        self.total_fired = checkpoint.get("total_fired", 0)
        self.no_diff_count = checkpoint.get("no_diff", 0)
        self._request_count = checkpoint.get("request_count", 0)
        # Restore payloads if available (skip if not in checkpoint - old format)
        if "payloads" in checkpoint:
            self.payloads = [
                PayloadCandidate(
                    parameter=ParameterModel(
                        name=p["parameter_name"],
                        location=p["parameter_location"],
                        inferred_type="unknown",
                        raw_value=p["payload"],
                    ),
                    payload=p["payload"],
                    attack_class=p["attack_class"],
                )
                for p in checkpoint["payloads"]
            ]
        # Restore fired identities for dedup
        self._fired_identities = set(checkpoint.get("fired_identities", []))
        # Note: hits and near_misses are not restored (would need to replay)
        return checkpoint

    async def run(
        self,
        on_result: Optional[ResultCallback] = None,
    ) -> dict[str, Any]:
        """Drive the payload loop.

        Args:
            on_result: Optional callback for each result (for progress reporting).

        Returns:
            Summary dict with stats and results.
        """
        self._start_time = time.monotonic()

        # Process payloads in batches
        i = 0
        _no_auth_reminder_time: Optional[float] = None
        while i < len(self.payloads):
            # Stage 0: Poll file-based kill switch from engagement context
            if self.scope_checker is not None and self.scope_checker.context.is_kill_switch_active():
                logger.warning("Kill switch activated — aborting payload loop")
                self._kill.set()
                break

            if self._kill.is_set():
                break

            # Periodic reminder: when running without engagement context, log
            # once per batch so it stays visible without per-request noise.
            if self.engagement_context is None:
                now = time.monotonic()
                if _no_auth_reminder_time is None or now - _no_auth_reminder_time >= 30.0:
                    logger.warning(
                        "Running without engagement context — scope, destructive-payload, "
                        "and kill-switch gates are disabled for this run."
                    )
                    _no_auth_reminder_time = now

            # Check max requests
            if self._request_count >= self.max_requests:
                break

            # Wait if paused (non-blocking check, then block on resume event)
            while self._paused and not self._kill.is_set():
                await self._resume_event.wait()

            # Determine batch size (may be less than batch_size for the last batch)
            batch_end = min(i + self.batch_size, len(self.payloads))
            batch = self.payloads[i:batch_end]

            # Fire batch concurrently (if batch_size > 1)
            if self.batch_size > 1:
                # Stage 88: Dedup check for concurrent batch mode
                deduped_batch = []
                for candidate in batch:
                    if (candidate.identity_hash in self._fired_identities or
                        any(c.identity_hash == candidate.identity_hash for c in deduped_batch)):
                        logger.debug(f"Skipping duplicate in batch: {candidate.identity_hash[:8]}")
                        self.no_diff_count += 1
                        self._request_count += 1
                        self.total_fired += 1
                    else:
                        deduped_batch.append(candidate)

                results = await asyncio.gather(
                    *[self._fire_single(candidate) for candidate in deduped_batch],
                    return_exceptions=True,
                )
                # Convert any exceptions to error PayloadResults
                results = [
                    r if isinstance(r, PayloadResult) else PayloadResult(
                        candidate=candidate,
                        status_code=0,
                        delta=None,
                        elapsed=0.0,
                    )
                    for candidate, r in zip(deduped_batch, results)
                ]
                # Track fired identities
                for candidate, result in zip(deduped_batch, results):
                    if isinstance(result, PayloadResult):
                        self._fired_identities.add(candidate.identity_hash)
            else:
                # Sequential mode
                results = []
                for candidate in batch:
                    # Stage 88: Dedup check
                    if candidate.identity_hash in self._fired_identities:
                        logger.debug(f"Skipping duplicate payload: {candidate.identity_hash[:8]}")
                        self.no_diff_count += 1
                        self._request_count += 1
                        self.total_fired += 1
                        continue

                    try:
                        result = await self._fire_single(candidate)
                        # Track fired identity
                        self._fired_identities.add(candidate.identity_hash)
                        results.append(result)
                    except ScopeError:
                        # Scope errors should propagate (kill switch, out of scope, etc.)
                        raise
                    except Exception as e:
                        error_result = PayloadResult(
                            candidate=candidate,
                            status_code=0,
                            delta=None,
                            elapsed=0.0,
                        )
                        if on_result:
                            on_result(error_result)
                        self._fired_identities.add(candidate.identity_hash)
                        self.no_diff_count += 1
                        self._request_count += 1
                        self.total_fired += 1
                        results.append(error_result)

            # Process batch results
            for result in results:
                if result is None or not isinstance(result, PayloadResult):
                    continue

                # Feed back to rate limiter
                if result.status_code >= 200 and result.status_code < 300:
                    self.rate_limiter.record_2xx()
                elif result.status_code == 429:
                    self.rate_limiter.record_429()

                # Stage 9.5: Recalibration check
                if result.delta:
                    self.recalibration.check_result({
                        "status_code": result.status_code,
                        "content_length": result.delta.content_length_delta,
                    })

                # Check for recalibration triggers
                if self.recalibration.needs_waf_rerun():
                    logger.warning(
                        "WAF behavior shift detected — re-run WAF detection recommended"
                    )
                    self.recalibration.state.waf_rechecked = False  # Reset after re-run

                if self.recalibration.needs_baseline_refresh():
                    logger.info("Baseline refresh needed — consider re-capturing baseline")
                    self.recalibration.add_baseline_sample(
                        self._to_dict(self.baseline)
                    )

                # Classify
                result.hit = result.delta.is_confirmed_hit if result.delta else False
                result.near_miss = result.delta.is_near_miss if result.delta else False

                # Collect results
                if result.hit:
                    self.hits.append(result)
                elif result.near_miss:
                    self.near_misses.append(result)
                else:
                    self.no_diff_count += 1

                if on_result:
                    on_result(result)

                self._request_count += 1
                self.total_fired += 1

            i = batch_end

        # Summary
        elapsed = time.monotonic() - self._start_time
        return {
            "total_fired": self.total_fired,
            "hits": len(self.hits),
            "near_misses": len(self.near_misses),
            "no_diff": self.no_diff_count,
            "elapsed_seconds": round(elapsed, 2),
            "requests_per_second": round(
                self.total_fired / elapsed, 2
            ) if elapsed > 0 else 0,
            "results": [r.to_dict() for r in self.hits + self.near_misses],
            "recalibration_stats": self.recalibration.get_stats(),
        }

    @staticmethod
    def _to_dict(baseline: BaselineFingerprint) -> dict[str, Any]:
        """Convert BaselineFingerprint to dict for recalibration.

        Args:
            baseline: BaselineFingerprint object

        Returns:
            Dictionary representation
        """
        return {
            "status_code": baseline.status_code,
            "content_length": baseline.content_length,
            "body_hash": baseline.body_hash,
            "avg_response_time": baseline.avg_response_time,
        }

    async def _fire_single(
        self, candidate: PayloadCandidate
    ) -> PayloadResult:
        """Fire a single payload and capture the result.

        Modifies the request_model in place to inject the payload, then sends.
        Restores original after.
        """
        # Stage 0: Scope check
        if self.scope_checker is not None:
            self.scope_checker.check(
                url=self.request_model.url,
                method=self.request_model.method,
                attack_class=candidate.attack_class,
                description=f"{candidate.attack_class} on {candidate.parameter.name}",
            )

        # Stage 8.5: Destructive payload gate
        if candidate.destructive and not self.allow_destructive:
            logger.warning(
                f"Refusing to fire destructive payload: {candidate.attack_class} "
                f"on {candidate.parameter.name} — pass allow_destructive=True to enable"
            )
            return PayloadResult(
                candidate=candidate,
                status_code=0,
                delta=None,
                elapsed=0.0,
                hit=False,
            )

        # Stage 2.5: Exfiltration prevention
        if self.host_allowlist is not None:
            from nagapasha.security.exfil import HostAllowlist
            guard = HostAllowlist(allowed=self.host_allowlist)
            if not guard.is_allowed(self.request_model.url):
                logger.warning(
                    f"Exfiltration blocked: {self.request_model.url} "
                    f"not in allowlist: {self.host_allowlist}"
                )
                return PayloadResult(
                    candidate=candidate,
                    status_code=0,
                    delta=None,
                    elapsed=0.0,
                    hit=False,
                )

        param = candidate.parameter
        original_value = param.raw_value

        # Build modified request model
        modified = self._build_request_with_payload(param, candidate.payload)

        # Send
        resp = await self.runner.send(modified)
        elapsed = resp.elapsed

        # Compute delta
        delta = compute_delta(
            baseline=self.baseline,
            status_code=resp.status_code,
            body=resp.body,
            headers=resp.headers,
            response_time=elapsed,
            payload=candidate.payload,
        )

        return PayloadResult(
            candidate=candidate,
            status_code=resp.status_code,
            delta=delta,
            elapsed=elapsed,
            response_body_preview=resp.body[:200] if resp.body else "",
        )

    def _build_request_with_payload(
        self,
        param: ParameterModel,
        payload: str,
    ) -> RequestModel:
        """Build a modified RequestModel with payload injected.

        Returns a copy of the request_model with the parameter replaced by payload.
        """
        modified = RequestModel(
            method=self.request_model.method,
            url=self.request_model.url,
            base_url=self.request_model.base_url,
            headers=dict(self.request_model.headers),
            cookies=dict(self.request_model.cookies),
            body=self.request_model.body,
            body_type=self.request_model.body_type,
            query_params=dict(self.request_model.query_params),
            path_segments=list(self.request_model.path_segments),
            parameters=list(self.request_model.parameters),
        )

        if param.location == "query":
            modified.query_params[param.name] = payload

        elif param.location == "body_json":
            # Inject into JSON body
            import json as _json
            try:
                body = _json.loads(modified.body or "{}")
                body[param.name] = payload
                modified.body = _json.dumps(body)
            except (ValueError, TypeError):
                # Fall through — keep original body
                pass

        elif param.location == "body_form":
            # Inject into form body (key=value)
            import urllib.parse
            try:
                params = urllib.parse.parse_qs(modified.body or "")
                params[param.name] = [payload]
                modified.body = urllib.parse.urlencode(params, doseq=True)
            except Exception:
                pass

        elif param.location == "body_multipart":
            # Inject into multipart body (similar to form but with boundary)
            import urllib.parse
            try:
                params = urllib.parse.parse_qs(modified.body or "", keep_blank_values=True)
                params[param.name] = [payload]
                # Rebuild as multipart-like format (simplified)
                modified.body = urllib.parse.urlencode(params, doseq=True)
            except Exception:
                pass

        elif param.location == "header":
            modified.headers[param.name] = payload

        elif param.location == "cookie":
            modified.cookies[param.name] = payload

        elif param.location == "path":
            # Replace the path segment
            if param.name in modified.path_segments:
                idx = modified.path_segments.index(param.name)
                modified.path_segments[idx] = payload
                modified.url = modified.base_url + "/" + "/".join(modified.path_segments)

        return modified


# ---------------------------------------------------------------------------
# Convenience: run with default settings
# ---------------------------------------------------------------------------

async def run_payloads(
    request_model: RequestModel,
    baseline_fingerprint: BaselineFingerprint,
    payloads: list[PayloadCandidate],
    rate_limit_pps: float = 4.0,
    rate_limit_burst: float = 10.0,
    max_requests: int = 1000,
    on_result: Optional[ResultCallback] = None,
) -> dict[str, Any]:
    """Convenience function to run payloads with default settings.

    Args:
        request_model: The original request model.
        baseline_fingerprint: Baseline for diffing.
        payloads: List of payload candidates.
        rate_limit_pps: Requests per second ceiling.
        rate_limit_burst: Token bucket burst capacity.
        max_requests: Hard cap on total requests.
        on_result: Optional callback for each result.

    Returns:
        Summary dict.
    """
    loop = PayloadLoop(
        request_model=request_model,
        baseline_fingerprint=baseline_fingerprint,
        payloads=payloads,
        rate_limit_pps=rate_limit_pps,
        rate_limit_burst=rate_limit_burst,
        max_requests=max_requests,
    )
    return await loop.run(on_result=on_result)
