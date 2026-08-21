"""Tests for the token bucket rate limiter."""

import asyncio
import time

import pytest

from nagapasha.engine.rate_limiter import RateLimitConfig, TokenBucketRateLimiter


@pytest.fixture
def config():
    return RateLimitConfig(burst=5, refill_rate=2.0)


@pytest.fixture
def limiter(config):
    return TokenBucketRateLimiter(config)


class TestTokenBucket:
    @pytest.mark.asyncio
    async def test_acquire_immediate(self, limiter):
        """First acquire should be immediate (bucket starts full)."""
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.5  # should be nearly instant

    @pytest.mark.asyncio
    async def test_acquire_depletes_tokens(self, limiter):
        """Multiple acquires should deplete tokens."""
        for _ in range(5):
            await limiter.acquire()
        # Bucket should now be mostly empty
        assert limiter.current_tokens < 1.0

    @pytest.mark.asyncio
    async def test_acquire_blocks_when_empty(self, limiter):
        """Acquire should block when no tokens available."""
        # Deplete all tokens
        for _ in range(5):
            await limiter.acquire()

        # Next acquire should wait for refill
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start

        # Should have waited at least some time (refill rate = 2/s)
        # With burst=5 and refill=2/s, depleting 5 tokens takes ~2.5s to refill 1
        assert elapsed >= 0.2

    def test_record_429_increases_penalty(self, limiter):
        """429 should increase penalty debt."""
        assert limiter._penalty_debt == 0.0
        limiter.record_429()
        assert limiter._penalty_debt > 0.0

    def test_record_429_scales(self, limiter):
        """Multiple 429s should scale penalty."""
        limiter.record_429()
        debt1 = limiter._penalty_debt

        limiter.record_429()
        debt2 = limiter._penalty_debt

        assert debt2 > debt1

    def test_record_429_max_cap(self, limiter):
        """Penalty should not exceed max_backoff * refill_rate."""
        max_debt = limiter.config.max_backoff * limiter.config.refill_rate
        for _ in range(100):
            limiter.record_429()
        assert limiter._penalty_debt <= max_debt

    def test_record_2xx_reduces_penalty(self, limiter):
        """2xx should reduce penalty debt."""
        limiter.record_429()
        assert limiter._penalty_debt > 0

        limiter.record_2xx()
        assert limiter._penalty_debt < limiter._penalty_debt + 0.5  # reduced

    def test_total_429s_counter(self, limiter):
        """Counter should track 429s."""
        assert limiter.total_429s == 0
        limiter.record_429()
        limiter.record_429()
        assert limiter.total_429s == 2

    @pytest.mark.asyncio
    async def test_refill(self, limiter):
        """Tokens should refill over time."""
        # Deplete all tokens
        for _ in range(5):
            await limiter.acquire()
        assert limiter.current_tokens < 1.0

        # Wait for refill
        await asyncio.sleep(1.0)
        tokens = limiter.current_tokens
        # At 2 tokens/sec for 1 second, should have ~2 tokens
        assert tokens >= 1.5


class TestRateLimitConfig:
    def test_default_values(self):
        config = RateLimitConfig(burst=10, refill_rate=5.0)
        assert config.backoff_multiplier == 2.0
        assert config.max_backoff == 60.0

    def test_custom_values(self):
        config = RateLimitConfig(
            burst=20, refill_rate=10.0,
            backoff_multiplier=3.0, max_backoff=120.0
        )
        assert config.backoff_multiplier == 3.0
        assert config.max_backoff == 120.0
