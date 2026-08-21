"""Integration tests for security gate wiring.

These tests verify that the security gates are actually called during execution,
not just that they exist in isolation.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from nagapasha.engine.payload_loop import PayloadLoop, PayloadCandidate
from nagapasha.engine.diff import BaselineFingerprint
from nagapasha.models.request_model import ParameterModel, RequestModel
from nagapasha.engagement import EngagementContext
from nagapasha.scope import ScopeChecker, ScopeError


def _make_param(**overrides):
    """Helper to create a ParameterModel."""
    defaults = {
        "name": "id",
        "location": "query",
        "raw_value": "1",
        "is_fuzz_target": True,
        "inferred_type": "free_text",
    }
    defaults.update(overrides)
    return ParameterModel(**defaults)


def _make_request(param: ParameterModel) -> RequestModel:
    """Helper to create a RequestModel."""
    return RequestModel(
        method="GET",
        url="https://example.com/api",
        base_url="https://example.com",
        headers={"Content-Type": "application/json"},
        cookies={},
        body=None,
        body_type=None,
        query_params={"id": param.raw_value},
        path_segments=["api"],
        parameters=[param],
    )


def _make_baseline() -> BaselineFingerprint:
    """Helper to create a BaselineFingerprint."""
    return BaselineFingerprint(
        status_code=200,
        content_length=1000,
        body_hash="abc123",
        avg_response_time=0.1,
        header_names=frozenset(["content-type"]),
        body_preview="OK",
    )


def _make_candidate(param: ParameterModel, payload: str, attack_class: str = "test",
                    destructive: bool = False) -> PayloadCandidate:
    """Helper to create a PayloadCandidate."""
    return PayloadCandidate(
        parameter=param,
        payload=payload,
        attack_class=attack_class,
        destructive=destructive,
    )


def _make_context(**overrides):
    """Helper to create a basic engagement context."""
    defaults = {
        "engagement_id": "test",
        "roe_hash": "sha256:test",
        "scope_allowlist": ["example.com"],
        "scope_denylist": [],
        "allowed_methods": ["GET", "POST"],
        "allowed_attack_classes": [],
        "time_window_start": datetime(2020, 1, 1, tzinfo=timezone.utc),
        "time_window_end": datetime(2030, 12, 31, tzinfo=timezone.utc),
        "authorized_by": "test@example.com",
    }
    defaults.update(overrides)
    return EngagementContext.create(**defaults)


class TestScopeEnforcementIntegration:
    """Tests that verify ScopeChecker is actually called during execution."""

    @pytest.mark.asyncio
    async def test_scope_rejects_out_of_scope_payload(self):
        """Every payload fired should pass scope check."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        ctx = _make_context(scope_allowlist=["example.com"])

        candidates = [_make_candidate(param, "x", "sqli")]
        req.url = "https://evil.com/api?id=x"  # Out of scope

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            engagement_context=ctx,
        )

        async def fake_send(_req):
            raise AssertionError("Should not be called -- scope rejected")

        loop.runner.send = fake_send

        with pytest.raises(ScopeError, match="out of scope"):
            await loop.run()

    @pytest.mark.asyncio
    async def test_scope_allows_in_scope_payload(self):
        """In-scope payload should pass scope check."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        ctx = _make_context(scope_allowlist=["example.com"])

        candidates = [_make_candidate(param, "x", "sqli")]
        req.url = "https://example.com/api?id=x"  # In scope

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            engagement_context=ctx,
        )

        sent = []
        async def fake_send(_req):
            sent.append(_req)
            # Return a mock response — body must be a real string for compute_delta
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.text = '{"status": "ok"}'
            resp.body = '{"status": "ok"}'
            resp.elapsed = 0.05
            resp.url = "https://example.com/api?id=x"
            return resp

        loop.runner.send = fake_send

        results = await loop.run()
        assert results["total_fired"] == 1
        assert len(sent) == 1


class TestDestructiveGateIntegration:
    """Tests that verify destructive payload gate is actually called."""

    @pytest.mark.asyncio
    async def test_destructive_payload_denied_by_default(self):
        """Destructive payloads should be skipped without allow_destructive."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        candidate = PayloadCandidate(
            parameter=param,
            payload=";cat /etc/passwd",
            attack_class="rce",
            destructive=True,
        )

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=[candidate],
            allow_destructive=False,  # default
        )

        async def fake_send(_req):
            raise AssertionError("Should not be called for denied destructive")

        loop.runner.send = fake_send

        results = await loop.run()
        # Payload was blocked by destructive gate, so no hits
        assert results["hits"] == 0
        # Total fired counts the blocked attempt
        assert results["total_fired"] == 1

    @pytest.mark.asyncio
    async def test_destructive_payload_fires_when_allowed(self):
        """Destructive payloads should fire with allow_destructive=True."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        candidate = PayloadCandidate(
            parameter=param,
            payload=";cat /etc/passwd",
            attack_class="rce",
            destructive=True,
        )

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=[candidate],
            allow_destructive=True,
        )

        sent = []
        async def fake_send(_req):
            sent.append(_req)
            # Return a mock response — body must be a real string for compute_delta
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.text = '{"status": "ok"}'
            resp.body = '{"status": "ok"}'
            resp.elapsed = 0.05
            resp.url = "https://example.com/api?id=1"
            return resp

        loop.runner.send = fake_send

        results = await loop.run()
        assert results["total_fired"] == 1
        assert len(sent) == 1


class TestBatchDedupIntegration:
    """Tests that verify dedup works in batch mode."""

    @pytest.mark.asyncio
    async def test_batch_dedup_works(self):
        """Dedup check must work in concurrent batch mode."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        # Two identical payloads
        candidates = [
            PayloadCandidate(
                parameter=param,
                payload="dup",
                attack_class="test",
                identity_hash="same-hash",
            ),
            PayloadCandidate(
                parameter=param,
                payload="dup",
                attack_class="test",
                identity_hash="same-hash",
            ),
        ]

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            batch_size=2,  # concurrent
            max_requests=10,
        )

        call_count = [0]

        async def fake_send(_req):
            call_count[0] += 1
            # Return a mock response — body must be a real string for compute_delta
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.text = '{"status": "ok"}'
            resp.body = '{"status": "ok"}'
            resp.elapsed = 0.05
            resp.url = "https://example.com/api?id=1"
            return resp

        loop.runner.send = fake_send

        results = await loop.run()
        # Only one should be actually fired (dedup works)
        assert call_count[0] == 1
        # Total fired counts both (one fired, one deduped)
        assert results["total_fired"] == 2


class TestExfilGuardIntegration:
    """Tests that verify exfil guard is called during execution."""

    @pytest.mark.asyncio
    async def test_exfil_guard_blocks_off_host(self):
        """Payloads targeting off-allowlist hosts should be blocked."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        req.url = "https://evil.com/api?id=x"

        candidates = [_make_candidate(param, "x")]

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            host_allowlist=["example.com"],
        )

        async def fake_send(_req):
            raise AssertionError("Should not be called")

        loop.runner.send = fake_send

        results = await loop.run()
        # Payload was blocked by exfil guard, so no hits
        assert results["hits"] == 0
        # Total fired counts the blocked attempt
        assert results["total_fired"] == 1


class TestKillSwitchIntegration:
    """Tests that verify kill switch is polled during execution."""

    @pytest.mark.asyncio
    async def test_file_kill_switch_halts_loop(self, tmp_path):
        """When kill_switch file exists, loop should stop."""
        import os
        import shutil

        original_cwd = os.getcwd()
        os.chdir(tmp_path)

        try:
            param = _make_param()
            req = _make_request(param)
            baseline = _make_baseline()

            ctx = _make_context()

            candidates = [_make_candidate(param, str(i)) for i in range(50)]
            loop = PayloadLoop(
                request_model=req,
                baseline_fingerprint=baseline,
                payloads=candidates,
                engagement_context=ctx,
            )

            # Write kill switch file
            from nagapasha.engagement import write_kill_switch
            write_kill_switch("test")

            results = await loop.run()
            # Should stop early, before all 50
            assert results["total_fired"] < 50
        finally:
            os.chdir(original_cwd)
            shutil.rmtree(tmp_path, ignore_errors=True)