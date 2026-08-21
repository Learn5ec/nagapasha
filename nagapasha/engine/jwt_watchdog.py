"""JWT detection and expiry watchdog.

Auto-detects JWTs in headers/cookies, decodes the payload, and provides
expiry monitoring with optional pause-on-expiry.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

_JWT_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]*$", re.MULTILINE
)


@dataclass
class JwtInfo:
    """Decoded JWT information."""

    is_jwt: bool = False
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    alg: Optional[str] = None
    exp: Optional[float] = None          # unix timestamp
    issued_at: Optional[float] = None    # iat claim
    is_expired: bool = False
    algorithm_flagged: bool = False      # alg: none or weak
    flag_reason: str = ""                # description of the flag

    @property
    def time_remaining(self) -> float:
        """Seconds until expiry (negative if already expired)."""
        if self.exp is None:
            return float("inf")
        return self.exp - time.time()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "is_jwt": self.is_jwt,
            "alg": self.alg,
            "exp": self.exp,
            "issued_at": self.issued_at,
            "is_expired": self.is_expired,
            "algorithm_flagged": self.algorithm_flagged,
            "flag_reason": self.flag_reason,
            "time_remaining": self.time_remaining,
        }
        # Only include header/payload if we have them (for reporting)
        if self.header or self.payload:
            d["header"] = self.header
            d["payload"] = self.payload
        return d


def _base64url_decode(s: str) -> bytes:
    """Decode a base64url-encoded string (no padding)."""
    # Add padding
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def decode_jwt(token: str) -> JwtInfo:
    """Decode a JWT without verifying the signature.

    Returns a JwtInfo object with parsed header, payload, and extracted claims.
    Flags weak algorithms (none, HS128 with no key).
    """
    info = JwtInfo()

    parts = token.split(".")
    if len(parts) < 2:
        return info

    info.is_jwt = True

    # Decode header
    try:
        header_bytes = _base64url_decode(parts[0])
        info.header = json.loads(header_bytes)
        info.alg = info.header.get("alg")
    except (ValueError, json.JSONDecodeError):
        return info

    # Flag weak algorithms
    weak_algs = {"none", "HS128"}
    if info.alg and info.alg.lower() == "none":
        info.algorithm_flagged = True
        info.flag_reason = "algorithm 'none' — no signature verification"
    elif info.alg in weak_algs:
        info.algorithm_flagged = True
        info.flag_reason = f"algorithm '{info.alg}' is weak"

    # Decode payload
    try:
        payload_bytes = _base64url_decode(parts[1])
        info.payload = json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        return info

    # Extract claims
    info.exp = info.payload.get("exp")
    info.issued_at = info.payload.get("iat")

    if info.exp is not None:
        info.is_expired = time.time() > info.exp
        if info.is_expired:
            info.flag_reason += (
                f" (expired {abs(info.exp - time.time()):.0f}s ago)"
            )

    return info


def detect_jwts(headers: dict[str, str], cookies: dict[str, str]) -> dict[str, JwtInfo]:
    """Scan headers and cookies for JWTs.

    Returns a dict mapping {header_or_cookie_name: JwtInfo}.
    """
    results: dict[str, JwtInfo] = {}

    jwt_names = {"Authorization", "authorization",
                 "cookie", "Cookie", "Set-Cookie"}

    for name, value in headers.items():
        # Look for "Bearer <token>" in Authorization
        lower_name = name.lower()
        if lower_name == "authorization" and value.startswith("Bearer "):
            token = value[len("Bearer "):].strip()
            if _JWT_PATTERN.match(token):
                info = decode_jwt(token)
                if info.is_jwt:
                    results[f"Authorization:Bearer"] = info

        # Check all headers for JWT-shaped values
        elif _JWT_PATTERN.match(value):
            info = decode_jwt(value)
            if info.is_jwt:
                results[name] = info

    for name, value in cookies.items():
        if _JWT_PATTERN.match(value):
            info = decode_jwt(value)
            if info.is_jwt:
                results[name] = info

    return results


class JwtWatchdog:
    """Background watchdog that monitors JWT expiry.

    When ``exp - pause_at`` is reached, it signals the engine to pause.
    """

    def __init__(
        self,
        jwt_info: Optional[JwtInfo] = None,
        pause_at_seconds_before_expiry: float = 60.0,
        on_pause: Optional[Callable[[], None]] = None,
    ) -> None:
        self.info = jwt_info or JwtInfo()
        self.pause_at_seconds = pause_at_seconds_before_expiry
        self.on_pause = on_pause
        self._cancelled = False
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the background monitoring task."""
        if self.info.exp is None:
            return  # no expiry to watch
        self._task = asyncio.create_task(self._monitor())

    async def cancel(self) -> None:
        """Stop the watchdog."""
        self._cancelled = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def wait_for_pause(self) -> None:
        """Block until paused or until expiry is too close."""
        if self._task:
            await self._task

    async def _monitor(self) -> None:
        assert self.info.exp is not None
        pause_at = self.info.exp - self.pause_at_seconds

        while not self._cancelled:
            remaining = self.info.exp - time.time()

            if remaining <= 0:
                # Already expired — trigger pause
                if self.on_pause:
                    self.on_pause()
                break

            if remaining <= self.pause_at_seconds:
                if self.on_pause:
                    self.on_pause()
                # Keep watching — may need to wait for a new token
                await asyncio.sleep(5)
                continue

            # Sleep until close to pause time
            sleep_time = min(remaining - self.pause_at_seconds, 30)
            await asyncio.sleep(max(sleep_time, 0.1))
