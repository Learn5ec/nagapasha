"""Tests for the response diffing engine."""

import pytest

from nagapasha.engine.diff import (
    BaselineFingerprint,
    ResponseDelta,
    compute_delta,
    compute_fingerprint,
)


@pytest.fixture
def baseline():
    return compute_fingerprint(
        status_code=200,
        body='{"status": "ok", "data": [1, 2, 3]}',
        headers={"Content-Type": "application/json"},
        response_time=0.045,
    )


class TestComputeDelta:
    def test_no_diff(self, baseline):
        """Same response should produce no diff."""
        delta = compute_delta(
            baseline,
            status_code=200,
            body='{"status": "ok", "data": [1, 2, 3]}',
            headers={"Content-Type": "application/json"},
            response_time=0.045,
        )
        assert delta.is_no_diff is True
        assert delta.is_confirmed_hit is False

    def test_status_change(self, baseline):
        """Status code change should be detected."""
        delta = compute_delta(
            baseline,
            status_code=500,
            body='{"error": "Fatal error: database connection lost"}',
            headers={"Content-Type": "application/json"},
            response_time=0.05,
        )
        assert delta.is_no_diff is False
        assert delta.status_delta == 300
        assert delta.is_confirmed_hit is True  # "Fatal error" matches signature

    def test_content_length_change(self, baseline):
        """Large content-length change should be detected."""
        long_body = '{"status": "ok", "data": [1, 2, 3]} ' + ("x" * 5000)
        delta = compute_delta(
            baseline,
            status_code=200,
            body=long_body,
            headers={"Content-Type": "application/json"},
            response_time=0.05,
        )
        assert delta.is_no_diff is False
        assert delta.content_length_delta > 0

    def test_reflected_payload(self, baseline):
        """Reflected payload should be detected."""
        delta = compute_delta(
            baseline,
            status_code=200,
            body='{"status": "ok", "data": ["<script>hello</script>"]}',
            headers={"Content-Type": "application/json"},
            response_time=0.05,
            payload="<script>",
        )
        assert delta.is_no_diff is False
        assert delta.has_reflected_payload is True

    def test_error_signature(self, baseline):
        """Error signature in response should be detected."""
        error_body = "SQL syntax error near 'SELECT'"
        delta = compute_delta(
            baseline,
            status_code=500,
            body=error_body,
            headers={"Content-Type": "text/html"},
            response_time=0.05,
        )
        assert delta.is_no_diff is False
        assert delta.has_error_signature is True
        assert delta.is_confirmed_hit is True

    def test_response_time_spike(self, baseline):
        """Large response time spike should be flagged as near-miss."""
        delta = compute_delta(
            baseline,
            status_code=200,
            body='{"status": "ok"}',
            headers={"Content-Type": "application/json"},
            response_time=2.0,  # way slower than 0.045 baseline
        )
        assert delta.is_no_diff is False
        assert delta.response_time_delta > 0
        assert delta.is_near_miss is True

    def test_near_miss_status_down(self, baseline):
        """Status 403 (down from 200) without error sig should be near-miss."""
        delta = compute_delta(
            baseline,
            status_code=403,
            body="Forbidden",
            headers={"Content-Type": "text/html"},
            response_time=0.05,
        )
        assert delta.is_no_diff is False
        assert delta.status_delta == 203  # 403 - 200
        assert delta.is_near_miss is True

    def test_delta_to_dict(self, baseline):
        delta = compute_delta(
            baseline,
            status_code=200,
            body='{"status": "ok"}',
            headers={"Content-Type": "application/json"},
            response_time=0.05,
        )
        d = delta.to_dict()
        assert isinstance(d, dict)
        assert "is_no_diff" in d
        assert "is_confirmed_hit" in d
        assert "delta_details" in d


class TestComputeFingerprint:
    def test_hash_length(self):
        fp = compute_fingerprint(200, "test", {}, 0.1)
        assert len(fp.body_hash) == 64  # SHA-256 hex digest
