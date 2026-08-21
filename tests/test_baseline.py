"""Tests for baseline capture and fingerprinting."""

import pytest

from nagapasha.engine.diff import (
    compute_fingerprint,
    BaselineFingerprint,
    check_flakiness,
)


class TestComputeFingerprint:
    def test_basic(self):
        fp = compute_fingerprint(
            status_code=200,
            body="Hello, world!",
            headers={"Content-Type": "text/html", "X-Custom": "val"},
            response_time=0.045,
        )
        assert fp.status_code == 200
        assert fp.content_length == 13
        assert len(fp.body_hash) == 64  # SHA-256 hex
        assert fp.avg_response_time == 0.045
        assert "content-type" in fp.header_names

    def test_body_hash_deterministic(self):
        """Same body should produce same hash."""
        fp1 = compute_fingerprint(200, "test body", {}, 0.1)
        fp2 = compute_fingerprint(200, "test body", {}, 0.2)
        assert fp1.body_hash == fp2.body_hash

    def test_body_hash_changes_with_body(self):
        """Different bodies should produce different hashes."""
        fp1 = compute_fingerprint(200, "body A", {}, 0.1)
        fp2 = compute_fingerprint(200, "body B", {}, 0.1)
        assert fp1.body_hash != fp2.body_hash

    def test_header_names_lowercase(self):
        fp = compute_fingerprint(200, "", {"X-Custom-Header": "v"}, 0.1)
        assert "x-custom-header" in fp.header_names
        assert "X-Custom-Header" not in fp.header_names


class TestBaselineFingerprint:
    def test_fingerprint_key(self):
        fp = compute_fingerprint(200, "test", {}, 0.1)
        key = fp.fingerprint_key
        assert key.startswith("200:")
        assert fp.body_hash in key

    def test_body_preview(self):
        long_body = "x" * 500
        fp = compute_fingerprint(200, long_body, {}, 0.1)
        assert len(fp.body_preview) == 200


class TestCheckFlakiness:
    def test_single_fingerprint_not_flaky(self):
        fp = compute_fingerprint(200, "ok", {}, 0.1)
        is_flaky, reason = check_flakiness([fp])
        assert is_flaky is False
        assert reason == ""

    def test_consistent_fingerprints_not_flaky(self):
        fps = [
            compute_fingerprint(200, "ok", {}, 0.1),
            compute_fingerprint(200, "ok", {}, 0.1),
            compute_fingerprint(200, "ok", {}, 0.1),
        ]
        is_flaky, reason = check_flakiness(fps)
        assert is_flaky is False

    def test_inconsistent_status_is_flaky(self):
        fps = [
            compute_fingerprint(200, "ok", {}, 0.1),
            compute_fingerprint(500, "error", {}, 0.1),
        ]
        is_flaky, reason = check_flakiness(fps)
        assert is_flaky is True
        assert "status" in reason.lower()

    def test_inconsistent_body_is_flaky(self):
        fps = [
            compute_fingerprint(200, "body A", {}, 0.1),
            compute_fingerprint(200, "body B", {}, 0.1),
        ]
        is_flaky, reason = check_flakiness(fps)
        assert is_flaky is True
        assert "hash" in reason.lower()

    def test_variable_timing_is_flaky(self):
        fps = [
            compute_fingerprint(200, "ok", {}, 0.1),
            compute_fingerprint(200, "ok", {}, 1.0),  # 10x slower
        ]
        is_flaky, reason = check_flakiness(fps)
        assert is_flaky is True
        assert "time" in reason.lower()
