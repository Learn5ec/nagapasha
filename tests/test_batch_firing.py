"""Tests for batch payload firing in PayloadLoop."""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from nagapasha.engine.payload_loop import PayloadLoop, PayloadCandidate
from nagapasha.engine.diff import BaselineFingerprint
from nagapasha.engine.runner import HttpxResponse
from nagapasha.models.request_model import RequestModel, ParameterModel


@pytest.fixture
def baseline():
    """Create a baseline fingerprint."""
    return BaselineFingerprint(
        status_code=200,
        content_length=100,
        body_hash="abc123",
        avg_response_time=0.05,
        header_names=frozenset(),
        body_preview="test",
    )


@pytest.fixture
def sample_request():
    """Create a sample RequestModel."""
    return RequestModel(
        method="GET",
        url="https://example.com/api",
        base_url="https://example.com",
        headers={"Accept": "application/json"},
    )


@pytest.fixture
def sample_payloads():
    """Create sample PayloadCandidates."""
    param = ParameterModel(
        name="id",
        location="query",
        raw_value="123",
        is_fuzz_target=True,
        inferred_type="int",
    )
    return [
        PayloadCandidate(parameter=param, payload="1'", attack_class="sql_injection"),
        PayloadCandidate(parameter=param, payload="1 OR 1=1", attack_class="sql_injection"),
        PayloadCandidate(parameter=param, payload="1; DROP TABLE", attack_class="sql_injection"),
    ]


def _mock_response():
    """Create a mock HttpxResponse."""
    return HttpxResponse(
        status_code=200,
        headers={},
        body="",
        elapsed=0.01,
        url="https://example.com/api",
    )


class TestBatchFiring:
    """Tests for batch firing configuration."""

    @pytest.mark.asyncio
    async def test_batch_size_one(self, sample_request, baseline, sample_payloads):
        """Should work with batch_size=1 (sequential)."""
        mock_runner = AsyncMock()
        mock_runner.send = AsyncMock(return_value=_mock_response())

        loop = PayloadLoop(
            request_model=sample_request,
            baseline_fingerprint=baseline,
            payloads=sample_payloads,
            batch_size=1,
            rate_limit_pps=100,
            rate_limit_burst=100,
        )
        loop.runner = mock_runner

        results = await loop.run()
        assert results["total_fired"] == 3

    @pytest.mark.asyncio
    async def test_batch_size_two(self, sample_request, baseline, sample_payloads):
        """Should work with batch_size=2."""
        mock_runner = AsyncMock()
        mock_runner.send = AsyncMock(return_value=_mock_response())

        loop = PayloadLoop(
            request_model=sample_request,
            baseline_fingerprint=baseline,
            payloads=sample_payloads,
            batch_size=2,
            rate_limit_pps=100,
            rate_limit_burst=100,
        )
        loop.runner = mock_runner

        results = await loop.run()
        assert results["total_fired"] == 3

    @pytest.mark.asyncio
    async def test_batch_size_exceeds_payloads(self, sample_request, baseline, sample_payloads):
        """Should handle batch_size > number of payloads."""
        mock_runner = AsyncMock()
        mock_runner.send = AsyncMock(return_value=_mock_response())

        loop = PayloadLoop(
            request_model=sample_request,
            baseline_fingerprint=baseline,
            payloads=sample_payloads,
            batch_size=10,
            rate_limit_pps=100,
            rate_limit_burst=100,
        )
        loop.runner = mock_runner

        results = await loop.run()
        assert results["total_fired"] == 3

    @pytest.mark.asyncio
    async def test_batch_calls_runner_correctly(self, sample_request, baseline, sample_payloads):
        """Should call runner.send for each payload."""
        mock_runner = AsyncMock()
        mock_runner.send = AsyncMock(return_value=_mock_response())

        loop = PayloadLoop(
            request_model=sample_request,
            baseline_fingerprint=baseline,
            payloads=sample_payloads,
            batch_size=3,  # fire all at once
            rate_limit_pps=100,
            rate_limit_burst=100,
        )
        loop.runner = mock_runner

        await loop.run()
        assert mock_runner.send.call_count == 3


class TestCheckpointResume:
    """Tests for checkpoint and resume."""

    def test_save_checkpoint(self, sample_request, baseline, sample_payloads, tmp_path):
        """Should save checkpoint to file."""
        loop = PayloadLoop(
            request_model=sample_request,
            baseline_fingerprint=baseline,
            payloads=sample_payloads,
        )
        loop.total_fired = 5
        loop.no_diff_count = 3
        loop._request_count = 10

        checkpoint_path = tmp_path / "checkpoint.json"
        loop.save_checkpoint(str(checkpoint_path))
        assert checkpoint_path.exists()

        data = json.loads(checkpoint_path.read_text())
        assert data["total_fired"] == 5
        assert data["no_diff"] == 3
        assert data["request_count"] == 10

    def test_load_checkpoint(self, sample_request, baseline, sample_payloads, tmp_path):
        """Should load checkpoint from file."""
        loop = PayloadLoop(
            request_model=sample_request,
            baseline_fingerprint=baseline,
            payloads=sample_payloads,
        )

        checkpoint_path = tmp_path / "checkpoint.json"
        checkpoint_path.write_text(
            json.dumps({
                "total_fired": 10,
                "hits": 0,
                "near_misses": 0,
                "no_diff": 8,
                "request_count": 20,
                "paused": False,
                "killed": False,
            })
        )
        loaded = loop.load_checkpoint(str(checkpoint_path))
        assert loaded["total_fired"] == 10
        assert loop.total_fired == 10
        assert loop.no_diff_count == 8
