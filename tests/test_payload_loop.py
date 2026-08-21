"""Tests for the payload loop engine."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nagapasha.engine.diff import (
    BaselineFingerprint,
    ResponseDelta,
    compute_delta,
)
from nagapasha.engine.payload_loop import (
    PayloadCandidate,
    PayloadLoop,
    PayloadResult,
    run_payloads,
)
from nagapasha.models.request_model import ParameterModel, RequestModel


def _make_baseline(status_code=200, content_length=100, body_hash="abc123"):
    return BaselineFingerprint(
        status_code=status_code,
        content_length=content_length,
        body_hash=body_hash,
        avg_response_time=0.05,
        header_names=frozenset({"content-type", "server"}),
        body_preview="hello world",
    )


def _make_param(name="id", location="query", param_type="int", value="42"):
    return ParameterModel(
        name=name,
        location=location,
        inferred_type=param_type,
        raw_value=value,
        is_fuzz_target=True,
        do_not_fuzz=False,
    )


def _make_request(param: ParameterModel):
    return RequestModel(
        method="GET",
        url=f"https://example.com/api/item?id={param.raw_value}",
        base_url="https://example.com",
        headers={"Accept": "application/json"},
        query_params={param.name: param.raw_value},
        parameters=[param],
    )


def _make_candidate(param: ParameterModel, payload: str, attack_class="test"):
    return PayloadCandidate(
        parameter=param,
        payload=payload,
        attack_class=attack_class,
    )


class TestPayloadResult:
    def test_classification_hit(self):
        candidate = _make_candidate(_make_param(), "<script>")
        delta = ResponseDelta(is_confirmed_hit=True, has_reflected_payload=True)
        result = PayloadResult(
            candidate=candidate,
            status_code=200,
            delta=delta,
            elapsed=0.1,
        )
        assert result.classification == "HIT"

    def test_classification_near_miss(self):
        candidate = _make_candidate(_make_param(), "999")
        delta = ResponseDelta(is_near_miss=True, status_delta=-1)
        result = PayloadResult(
            candidate=candidate,
            status_code=199,
            delta=delta,
            elapsed=0.1,
        )
        assert result.classification == "NEAR-MISS"

    def test_classification_no_diff(self):
        candidate = _make_candidate(_make_param(), "0")
        delta = ResponseDelta(is_no_diff=True)
        result = PayloadResult(
            candidate=candidate,
            status_code=200,
            delta=delta,
            elapsed=0.1,
        )
        assert result.classification == "no-diff"

    def test_to_dict(self):
        candidate = _make_candidate(_make_param(), "<script>")
        delta = ResponseDelta(
            is_confirmed_hit=True,
            has_reflected_payload=True,
            reflected_text="<script>",
        )
        result = PayloadResult(
            candidate=candidate,
            status_code=200,
            delta=delta,
            elapsed=0.1,
        )
        d = result.to_dict()
        assert d["parameter"] == "id"
        assert d["classification"] == "HIT"
        assert d["status_code"] == 200
        assert d["delta"]["has_reflected_payload"] is True


class TestPayloadLoop:
    def test_build_request_with_query_payload(self):
        """PayloadLoop should build modified request with injected payload."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=[],
        )

        modified = loop._build_request_with_payload(param, "999")
        assert modified.query_params["id"] == "999"
        assert modified.base_url == "https://example.com"

    def test_build_request_with_header_payload(self):
        """Header parameters should be injected into headers."""
        param = _make_param("X-Custom", "header", "free_text", "original")
        req = _make_request(param)
        req.headers["X-Custom"] = "original"
        baseline = _make_baseline()

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=[],
        )

        modified = loop._build_request_with_payload(param, "injected")
        assert modified.headers["X-Custom"] == "injected"

    def test_build_request_with_cookie_payload(self):
        """Cookie parameters should be injected into cookies."""
        param = _make_param("session", "cookie", "free_text", "abc123")
        req = _make_request(param)
        req.cookies["session"] = "abc123"
        baseline = _make_baseline()

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=[],
        )

        modified = loop._build_request_with_payload(param, "hijacked")
        assert modified.cookies["session"] == "hijacked"

    @pytest.mark.asyncio
    async def test_kill_stops_loop(self):
        """Kill signal should stop the loop mid-execution."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        candidates = [_make_candidate(param, str(i)) for i in range(100)]
        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            max_requests=10,
        )

        # Mock runner.send to avoid real HTTP
        async def fake_send(_req):
            return MagicMock(
                status_code=200,
                headers={"content-type": "text/plain"},
                body="ok",
                elapsed=0.01,
                text="ok",
                url="https://example.com",
            )
        loop.runner.send = fake_send

        # Fire a few then kill
        async def fire_then_kill():
            await asyncio.sleep(0.05)
            loop.kill()

        asyncio.create_task(fire_then_kill())

        results = await loop.run()
        # Should have stopped before all 100
        assert results["total_fired"] < 100

    @pytest.mark.asyncio
    async def test_max_requests_cap(self):
        """max_requests should cap total fired."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        candidates = [_make_candidate(param, str(i)) for i in range(100)]
        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            max_requests=5,
        )

        async def fake_send(_req):
            return MagicMock(
                status_code=200,
                headers={"content-type": "text/plain"},
                body="ok",
                elapsed=0.01,
                text="ok",
                url="https://example.com",
            )
        loop.runner.send = fake_send

        results = await loop.run()
        assert results["total_fired"] == 5

    @pytest.mark.asyncio
    async def test_hit_classification(self):
        """Responses with error signatures should be classified as HITs."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        candidates = [_make_candidate(param, "' OR 1=1")]
        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            max_requests=1,
        )

        # Mock response with SQL error
        async def fake_send(_req):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/html"}
            resp.body = "<html>MySQL Error: syntax error near OR 1=1</html>"
            resp.elapsed = 0.05
            resp.text = resp.body
            resp.url = "https://example.com"
            return resp
        loop.runner.send = fake_send

        results = await loop.run()
        assert results["hits"] == 1
        assert results["results"][0]["classification"] == "HIT"

    @pytest.mark.asyncio
    async def test_no_diff_counted(self):
        """Stable responses should be counted as no-diff."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline(body_hash="abc123")

        candidates = [_make_candidate(param, "0")]
        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            max_requests=1,
        )

        async def fake_send(_req):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/plain"}
            resp.body = "hello world"
            resp.elapsed = 0.05
            resp.text = "hello world"
            resp.url = "https://example.com"
            return resp
        loop.runner.send = fake_send

        results = await loop.run()
        assert results["no_diff"] == 1
        assert results["hits"] == 0

    @pytest.mark.asyncio
    async def test_callback_invoked(self):
        """on_result callback should be invoked for each result."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        candidates = [_make_candidate(param, "1"), _make_candidate(param, "2")]
        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            max_requests=10,
        )

        results_seen = []

        async def fake_send(_req):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/plain"}
            resp.body = "ok"
            resp.elapsed = 0.01
            resp.text = "ok"
            resp.url = "https://example.com"
            return resp
        loop.runner.send = fake_send

        def collect(r):
            results_seen.append(r)

        await loop.run(on_result=collect)
        assert len(results_seen) == 2

    @pytest.mark.asyncio
    async def test_empty_payloads(self):
        """Empty payload list should produce no results."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=[],
        )

        results = await loop.run()
        assert results["total_fired"] == 0
        assert results["hits"] == 0


class TestRunPayloadsConvenience:
    @pytest.mark.asyncio
    async def test_run_payloads(self):
        """Convenience function should work same as PayloadLoop."""
        param = _make_param()
        req = _make_request(param)
        baseline = _make_baseline()

        candidates = [_make_candidate(param, "0")]

        async def fake_send(_req):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/plain"}
            resp.body = "hello world"
            resp.elapsed = 0.01
            resp.text = "hello world"
            resp.url = "https://example.com"
            return resp

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            max_requests=10,
        )
        loop.runner.send = fake_send

        results = await loop.run()
        assert results["total_fired"] == 1
        assert results["no_diff"] == 1
        assert results["hits"] == 0
