"""Tests for the dry-run runner module."""

import asyncio
import pytest

from nagapasha.engine.dry_run import DryRunRunner
from nagapasha.models.request_model import RequestModel


@pytest.fixture
def dry_runner():
    """Create a DryRunRunner instance."""
    return DryRunRunner()


@pytest.fixture
def sample_request():
    """Create a sample RequestModel."""
    return RequestModel(
        method="POST",
        url="https://example.com/api/test",
        base_url="https://example.com",
        headers={"Content-Type": "application/json"},
        cookies={"session": "abc123"},
        body='{"key": "value"}',
        body_type="json",
    )


class TestDryRunRunner:
    """Tests for DryRunRunner."""

    @pytest.mark.asyncio
    async def test_send_returns_mock_response(self, dry_runner, sample_request):
        """Should return a mock HttpxResponse without sending."""
        response = await dry_runner.send(sample_request)
        assert response.status_code == 200
        assert response.headers == {}
        assert response.body == ""
        assert response.elapsed == 0.0
        assert response.url == sample_request.url

    @pytest.mark.asyncio
    async def test_send_logs_request(self, dry_runner, sample_request):
        """Should log the request details."""
        await dry_runner.send(sample_request)
        logged = dry_runner.get_logged_requests()
        assert len(logged) == 1
        assert logged[0]["method"] == "POST"
        assert logged[0]["url"] == sample_request.url

    @pytest.mark.asyncio
    async def test_send_multiple(self, dry_runner, sample_request):
        """Should send multiple simulated requests."""
        responses = await dry_runner.send_multiple(sample_request, count=3)
        assert len(responses) == 3
        for resp in responses:
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_request_count_increments(self, dry_runner, sample_request):
        """Should track request count."""
        await dry_runner.send(sample_request)
        await dry_runner.send(sample_request)
        logged = dry_runner.get_logged_requests()
        assert len(logged) == 2
        assert logged[0]["request_count"] == 1
        assert logged[1]["request_count"] == 2

    @pytest.mark.asyncio
    async def test_clear_log(self, dry_runner, sample_request):
        """Should clear the request log."""
        await dry_runner.send(sample_request)
        dry_runner.clear_log()
        assert len(dry_runner.get_logged_requests()) == 0

    @pytest.mark.asyncio
    async def test_close_is_noop(self, dry_runner):
        """Should not raise on close."""
        await dry_runner.close()
