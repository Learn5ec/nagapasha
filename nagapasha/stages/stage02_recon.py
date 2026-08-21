"""Stage 2 — Recon / Baseline Agent (deterministic, no LLM).

Performs:
  (a) Auth validity check — replay the request, confirm expected 2xx
  (b) JWT detection & expiry watchdog
  (c) Baseline capture — 3-5 calibrations for fingerprinting
  (d) Rate-limit discovery — headers or conservative calibration
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Optional

from nagapasha.engine.baseline import capture_baseline
from nagapasha.engine.diff import BaselineFingerprint
from nagapasha.engine.jwt_watchdog import JwtInfo, detect_jwts
from nagapasha.engine.rate_limiter import RateLimitConfig, TokenBucketRateLimiter
from nagapasha.engine.runner import HttpRunner
from nagapasha.models.request_model import RequestModel


@dataclass
class ReconResult:
    """Outputs from the recon stage."""

    auth_valid: Optional[bool] = None
    auth_status: Optional[int] = None
    jwt_info: Optional[JwtInfo] = None
    jwt_jwts: dict[str, JwtInfo] = None  # name → JwtInfo
    baseline_fingerprint: Optional[BaselineFingerprint] = None
    is_flaky: bool = False
    flakiness_reason: str = ""
    rate_limit_pps: Optional[float] = None
    rate_limit_config: Optional[RateLimitConfig] = None
    rate_headers_read: dict[str, str] = None
    tech_stack: dict[str, Any] = None
    waf_detected: bool = False
    waf_name: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "auth_valid": self.auth_valid,
            "auth_status": self.auth_status,
            "is_flaky": self.is_flaky,
            "flakiness_reason": self.flakiness_reason,
            "rate_limit_pps": self.rate_limit_pps,
            "rate_limit_config": (
                {"burst": self.rate_limit_config.burst,
                 "refill_rate": self.rate_limit_config.refill_rate}
                if self.rate_limit_config else None
            ),
            "rate_headers_read": self.rate_headers_read or {},
            "tech_stack": self.tech_stack or {},
            "waf_detected": self.waf_detected,
            "waf_name": self.waf_name,
        }
        if self.jwt_info:
            d["jwt_info"] = self.jwt_info.to_dict()
        if self.jwt_jwts:
            d["jwt_jwts"] = {k: v.to_dict() for k, v in self.jwt_jwts.items()}
        if self.baseline_fingerprint:
            d["baseline_fingerprint"] = {
                "status_code": self.baseline_fingerprint.status_code,
                "content_length": self.baseline_fingerprint.content_length,
                "body_hash": self.baseline_fingerprint.body_hash[:32] + "...",
                "avg_response_time": self.baseline_fingerprint.avg_response_time,
            }
        return d


# WAF/CDN detection patterns
WAF_SIGNATURES: list[tuple[str, str]] = [
    ("cloudflare", re.compile(r"cf-ray|cf-cache-status|__cfduid|cloudflare", re.I)),
    ("akamai", re.compile(r"x-akamaisoft|x-akamai-transformed|akamai", re.I)),
    ("aws_waf", re.compile(r"x-amz-cf-id|x-amzn-requestid|amazon", re.I)),
    ("f5_bigip", re.compile(r"x-syncserver|x-request-id|bigip|big-ip", re.I)),
    ("sucuri", re.compile(r"sucuri|var-sucuri", re.I)),
    ("imperva", re.compile(r"x-imperva|incapsula", re.I)),
]


def detect_waf(headers: dict[str, str]) -> tuple[bool, Optional[str]]:
    """Detect WAF/CDN from response headers.

    Returns (detected, waf_name).
    """
    combined = " ".join(headers.values())
    for name, pattern in WAF_SIGNATURES:
        if pattern.search(combined):
            return True, name
    return False, None


def detect_tech_stack(headers: dict[str, str], baseline_fp: Optional[BaselineFingerprint]) -> dict[str, Any]:
    """Auto-fingerprint the tech stack from headers and baseline.

    Returns a dict with detected tech stack components.
    """
    tech: dict[str, Any] = {}

    # Server header
    server = headers.get("Server", "")
    if server:
        tech["server"] = server
        # Detect common servers
        if "nginx" in server.lower():
            tech["web_server"] = "nginx"
        elif "apache" in server.lower():
            tech["web_server"] = "apache"
        elif "iis" in server.lower():
            tech["web_server"] = "iis"
        elif "caddy" in server.lower():
            tech["web_server"] = "caddy"

    # X-Powered-By header
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        tech["powered_by"] = powered_by
        pb_lower = powered_by.lower()
        if "express" in pb_lower or "fastify" in pb_lower:
            tech["framework"] = "node.js"
        elif "php" in pb_lower:
            tech["language"] = "php"
        elif "django" in pb_lower or "flask" in pb_lower:
            tech["language"] = "python"
        elif "rails" in pb_lower:
            tech["framework"] = "ruby-on-rails"

    # Cookie-based framework detection
    known_session_cookies = {
        "JSESSIONID": "java/tomcat",
        "laravel_session": "laravel",
        "PHPSESSID": "php",
        "ASP.NET_SessionId": "asp.net",
        "rails_session": "rails",
    }
    # We don't have cookies here, but we can check response headers
    # Set-Cookie headers might reveal session management
    for name, tech_label in known_session_cookies.items():
        if name.lower() in " ".join(headers.keys()).lower():
            tech.setdefault("session_management", [])
            tech["session_management"].append(tech_label)

    # Database hints from error pages (if we have baseline)
    if baseline_fp and baseline_fp.body_preview:
        body_lower = baseline_fp.body_preview.lower()
        if "mysql" in body_lower:
            tech.setdefault("database_hints", [])
            tech["database_hints"].append("mysql")
        elif "postgres" in body_lower or "postgresql" in body_lower:
            tech.setdefault("database_hints", [])
            tech["database_hints"].append("postgres")
        elif "mongodb" in body_lower:
            tech.setdefault("database_hints", [])
            tech["database_hints"].append("mongodb")
        elif "oracle" in body_lower:
            tech.setdefault("database_hints", [])
            tech["database_hints"].append("oracle")

    return tech


async def run_recon(
    request_model: RequestModel,
    runner: HttpRunner,
    calibrate_count: int = 5,
) -> ReconResult:
    """Run the full recon pipeline on a RequestModel.

    Args:
        request_model: Parsed request model from Stage 1.
        runner: HTTP runner with rate limiter.
        calibrate_count: Number of baseline calibration fires.

    Returns:
        ReconResult with all outputs.
    """
    result = ReconResult()

    # (a) Auth validity check
    resp = await runner.send(request_model)
    result.auth_status = resp.status_code
    result.auth_valid = 200 <= resp.status_code < 300

    # (b) JWT detection
    jwts = detect_jwts(request_model.headers, request_model.cookies)
    if jwts:
        # Use the first JWT found (usually Authorization)
        first_jwt_name = next(iter(jwts))
        result.jwt_info = jwts[first_jwt_name]
        result.jwt_jwts = jwts

    # (c) Baseline capture
    try:
        fingerprint, is_flaky, reason = await capture_baseline(
            runner, request_model, count=calibrate_count
        )
        result.baseline_fingerprint = fingerprint
        result.is_flaky = is_flaky
        result.flakiness_reason = reason
    except Exception as e:
        result.is_flaky = True
        result.flakiness_reason = f"Baseline capture failed: {e}"

    # (d) Rate-limit discovery from response headers
    rl_headers = {}
    for key in ("X-RateLimit-Limit", "X-RateLimit-Remaining",
                "X-RateLimit-Reset", "Retry-After", "X-RateLimit-Reset"):
        if key in resp.headers:
            rl_headers[key] = resp.headers[key]

    result.rate_headers_read = rl_headers

    # Parse rate limit headers
    if "X-RateLimit-Limit" in rl_headers:
        try:
            burst = float(rl_headers["X-RateLimit-Limit"])
            # Default refill rate to burst / 10 (reasonable default)
            refill_rate = burst / 10.0
            result.rate_limit_pps = refill_rate
            result.rate_limit_config = RateLimitConfig(
                burst=burst,
                refill_rate=refill_rate,
            )
        except (ValueError, TypeError):
            pass

    # If we got a 429, adjust the limit
    if resp.status_code == 429:
        # Conservative: halve the burst
        if result.rate_limit_config:
            result.rate_limit_config.burst = max(1, result.rate_limit_config.burst / 2)
            result.rate_limit_pps = result.rate_limit_config.refill_rate * 0.5

    # Fallback: if no rate-limit info, use conservative defaults
    if result.rate_limit_config is None:
        default_burst = 10
        default_rate = 4.0
        result.rate_limit_pps = default_rate
        result.rate_limit_config = RateLimitConfig(
            burst=default_burst,
            refill_rate=default_rate,
        )

    # Tech stack detection
    result.tech_stack = detect_tech_stack(resp.headers, result.baseline_fingerprint)

    # WAF detection
    result.waf_detected, result.waf_name = detect_waf(resp.headers)

    return result
