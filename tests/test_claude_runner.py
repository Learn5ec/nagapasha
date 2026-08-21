"""Tests for the AnthropicRunner with retry and token tracking."""

import json
import time

import pytest
import asyncio

from nagapasha.llm.runner import AnthropicRunner, AnthropicInvocationError


class TestAnthropicRunner:
    """Tests for AnthropicRunner."""

    def test_call_count(self):
        """Should track invocation count."""
        runner = AnthropicRunner(retry_max=1, timeout=1)
        assert runner.call_count == 0

    def test_last_tokens_empty_initially(self):
        """Should start with empty last_tokens."""
        runner = AnthropicRunner()
        assert runner.last_tokens == {}

    def test_reset_stats(self):
        """Should reset call count and token tracker."""
        runner = AnthropicRunner()
        runner._call_count = 5
        runner.token_tracker = {"total": 100, "strategist": 50}
        runner._last_tokens = {"input": 10, "output": 5}
        runner.reset_stats()
        assert runner.call_count == 0
        assert runner.token_tracker == {}
        assert runner.last_tokens == {}

    def test_constructor_defaults(self):
        """Should have sensible defaults from .env config."""
        runner = AnthropicRunner()
        assert runner.retry_max == 2
        assert runner.retry_backoff == 2.0
        assert runner.timeout == 240

    def test_constructor_custom(self):
        """Should accept custom parameters."""
        runner = AnthropicRunner(
            retry_max=5,
            retry_backoff=1.5,
            timeout=60,
            token_tracker={"total": 0},
        )
        assert runner.retry_max == 5
        assert runner.retry_backoff == 1.5
        assert runner.timeout == 60


class TestAnthropicRunnerRetry:
    """Tests for retry behavior."""

    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        """Should retry on AnthropicInvocationError."""
        call_count = 0

        class FakeRunner(AnthropicRunner):
            async def _invoke_once(self, stage, context, timeout):
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise AnthropicInvocationError("transient error")
                return {"status": "ok", "data": {"result": "success"}, "tokens_used": {}}

        runner = FakeRunner(retry_max=3, retry_backoff=0.001)
        result = await runner.invoke("test_stage", {"context": "test"})
        assert result["status"] == "ok"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_raises_after_all_retries(self):
        """Should raise after exhausting all retries."""
        class FakeRunner(AnthropicRunner):
            async def _invoke_once(self, stage, context, timeout):
                raise AnthropicInvocationError("always fails")

        runner = FakeRunner(retry_max=2, retry_backoff=0.001)
        with pytest.raises(AnthropicInvocationError, match="failed after 2 attempts"):
            await runner.invoke("test_stage", {"context": "test"})

    @pytest.mark.asyncio
    async def test_no_retry_on_success(self):
        """Should not retry on first success."""
        call_count = 0

        class FakeRunner(AnthropicRunner):
            async def _invoke_once(self, stage, context, timeout):
                nonlocal call_count
                call_count += 1
                return {"status": "ok", "data": {}, "tokens_used": {}}

        runner = FakeRunner(retry_max=3, retry_backoff=0.001)
        await runner.invoke("test_stage", {"context": "test"})
        assert call_count == 1


class TestAnthropicRunnerTokenTracking:
    """Tests for token usage tracking."""

    @pytest.mark.asyncio
    async def test_records_tokens(self):
        """Should record token usage from results."""
        tracker = {}
        call_count = 0

        class FakeRunner(AnthropicRunner):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
            async def _invoke_once(self, stage, context, timeout):
                nonlocal call_count
                call_count += 1
                return {
                    "status": "ok",
                    "data": {"result": "test"},
                    "tokens_used": {"input": 100, "output": 50},
                }

        runner = FakeRunner(token_tracker=tracker)
        await runner.invoke("test_stage", {"context": "test"})
        assert runner.last_tokens == {"input": 100, "output": 50}
        assert tracker["total"] == 150

    @pytest.mark.asyncio
    async def test_accumulates_tokens(self):
        """Should accumulate token usage across calls."""
        tracker = {}
        call_count = 0

        class FakeRunner(AnthropicRunner):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
            async def _invoke_once(self, stage, context, timeout):
                nonlocal call_count
                call_count += 1
                return {
                    "status": "ok",
                    "data": {},
                    "tokens_used": {"input": 100, "output": 50},
                }

        runner = FakeRunner(token_tracker=tracker)
        await runner.invoke("test_stage", {"context": "test"})
        await runner.invoke("test_stage", {"context": "test"})
        assert tracker["total"] == 300

    @pytest.mark.asyncio
    async def test_tracks_per_stage(self):
        """Should track token usage per stage."""
        tracker = {}

        class FakeRunner(AnthropicRunner):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
            async def _invoke_once(self, stage, context, timeout):
                return {
                    "status": "ok",
                    "data": {},
                    "tokens_used": {"input": 100, "output": 50},
                }

        runner = FakeRunner(token_tracker=tracker)
        await runner.invoke("strategist", {"context": "test"})
        assert tracker.get("strategist") == 150
