"""Tests for the triage engine."""

import pytest

from nagapasha.engine.diff import BaselineFingerprint
from nagapasha.engine.triage import TriageResult, triage


def _make_baseline(status_code=200, content_length=100, body_hash="abc123"):
    return BaselineFingerprint(
        status_code=status_code,
        content_length=content_length,
        body_hash=body_hash,
        avg_response_time=0.05,
        header_names=frozenset(),
        body_preview="hello world",
    )


class TestTriage:
    def test_no_diff(self):
        """Matching baseline should be no-diff."""
        import hashlib
        body = "hello world"
        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        baseline = _make_baseline(body_hash=body_hash, content_length=len(body))
        result = triage(
            baseline=baseline,
            status_code=200,
            body=body,
            headers={},
            response_time=0.05,
        )
        assert result.is_no_diff is True
        assert result.is_hit is False
        assert result.is_ambiguous is False
        assert result.confidence == 1.0

    def test_hit_error_signature(self):
        """Response with error signature should be a hit."""
        baseline = _make_baseline()
        result = triage(
            baseline=baseline,
            status_code=200,
            body="MySQL Error: syntax error near OR 1=1",
            headers={},
            response_time=0.05,
            payload="' OR 1=1",
        )
        assert result.is_hit is True
        assert result.is_no_diff is False
        assert result.confidence >= 0.90
        assert any("error-signature" in e for e in result.evidence)

    def test_hit_reflected_payload(self):
        """Response with reflected payload should be a hit."""
        baseline = _make_baseline()
        result = triage(
            baseline=baseline,
            status_code=200,
            body="<html><script>alert(1)</script></html>",
            headers={},
            response_time=0.05,
            payload="<script>alert(1)</script>",
        )
        assert result.is_hit is True
        assert any("reflected" in e for e in result.evidence)

    def test_hit_large_status_change(self):
        """Large status code change should be a hit."""
        baseline = _make_baseline(status_code=200)
        result = triage(
            baseline=baseline,
            status_code=500,
            body="Internal Server Error",
            headers={},
            response_time=0.05,
        )
        assert result.is_hit is True
        assert result.confidence >= 0.70

    def test_ambiguous_status_delta(self):
        """Small status delta should be ambiguous."""
        baseline = _make_baseline(status_code=200)
        result = triage(
            baseline=baseline,
            status_code=203,
            body="Different content",
            headers={},
            response_time=0.05,
        )
        assert result.is_ambiguous is True
        assert result.is_hit is False

    def test_ambiguous_body_changed(self):
        """Body changed without clear signal should be ambiguous."""
        baseline = _make_baseline(body_hash="abc123")
        result = triage(
            baseline=baseline,
            status_code=200,
            body="completely different content here",
            headers={},
            response_time=0.05,
        )
        assert result.is_ambiguous is True
        assert result.is_hit is False

    def test_to_dict(self):
        """TriageResult.to_dict should return string values."""
        result = TriageResult(
            is_hit=False,
            is_no_diff=True,
            is_ambiguous=False,
            confidence=1.0,
            evidence=["test"],
        )
        d = result.to_dict()
        assert d["is_no_diff"] == "True"
        assert d["confidence"] == "1.00"
        assert d["evidence"] == "test"
