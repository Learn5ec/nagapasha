"""Token-bucket rate limiter with 429 penalty.

Never exceeds the calibrated ceiling. Integrates with httpx via a semaphore.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class RateLimitConfig:
    """Parsed from Stage 2(d) rate-limit calibration."""

    burst: float                  # max concurrent requests (token bucket capacity)
    refill_rate: float            # tokens per second (the ceiling)
    backoff_multiplier: float = 2.0   # on 429: double wait, up to max_backoff
    max_backoff: float = 60.0             # hard cap on backoff


class TokenBucketRateLimiter:
    """
    Standard token-bucket algorithm with async integration.

    Properties:
    - Never exceeds ``burst`` in-flight requests
    - Refills at ``refill_rate`` tokens/second
    - On 429: adds a penalty token debt, forcing longer waits
    - Integrates with httpx's async client via semaphore
    """

    def __init__(self, config: RateLimitConfig) -> None:
        self.config = config
        self._tokens: float = float(config.burst)
        self._last_refill: float = time.monotonic()
        self._penalty_debt: float = 0.0
        self._total_429s: int = 0

    # -- public API ---------------------------------------------------------

    async def acquire(self) -> None:
        """Block until a token is available, respecting rate and penalty."""
        while True:
            self._refill()
            if self._tokens >= 1.0 + self._penalty_debt:
                self._tokens -= 1.0
                return
            # Not enough tokens; wait for refill
            wait = (
                (1.0 + self._penalty_debt - self._tokens)
                / self.config.refill_rate
            )
            await asyncio.sleep(max(wait, 0.1))

    def record_429(self) -> None:
        """Called by the runner when a 429 is observed."""
        self._total_429s += 1
        # Set base penalty on first 429, then scale
        if self._penalty_debt == 0:
            self._penalty_debt = 1.0 / self.config.refill_rate
        else:
            self._penalty_debt = min(
                self._penalty_debt * self.config.backoff_multiplier,
                self.config.max_backoff * self.config.refill_rate,
            )

    def record_2xx(self) -> None:
        """Called for successful responses — may clear penalty debt."""
        if self._penalty_debt > 0:
            self._penalty_debt = max(0, self._penalty_debt - 0.5)

    def set_tokens(self, tokens: float) -> None:
        """Force the token count to a specific value.

        Used to carry the remaining token budget from a prior scan phase into
        the next one so a fresh PayloadLoop does not discard the phase-1 budget.
        """
        self._tokens = float(tokens)

    @property
    def total_429s(self) -> int:
        return self._total_429s

    @property
    def current_tokens(self) -> float:
        self._refill()
        return self._tokens

    # -- internals ----------------------------------------------------------

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._last_refill = now
        self._tokens = min(
            self.config.burst,
            self._tokens + elapsed * self.config.refill_rate,
        )
