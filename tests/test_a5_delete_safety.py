"""A5 tests: DELETE-method safety — irreversible gate by method, not just payload class.

Verifies:
- DELETE method without allow_irreversible_delete blocks all payloads
- DELETE method with allow_irreversible_delete allows payloads but marks destructive
- Non-irreversible methods (GET, POST) don't trigger the gate
- Payload without destructive flag on DELETE endpoint still triggers gate
- restorable=False for DELETE endpoints
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from dataclasses import dataclass, field

from nagapasha.engine.payload_loop import (
    PayloadLoop,
    PayloadCandidate,
    PayloadResult,
    IRREVERSIBLE_METHODS,
)
from nagapasha.models.request_model import RequestModel, ParameterModel
from nagapasha.engine.diff import BaselineFingerprint


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_param(name="test_param", location="query") -> ParameterModel:
    return ParameterModel(
        name=name,
        location=location,
        inferred_type="free_text",
        raw_value="test",
        is_fuzz_target=True,
        do_not_fuzz=False,
    )


def _make_req(method="GET") -> RequestModel:
    return RequestModel(
        method=method,
        url="http://example.com/api/resource/1",
        base_url="http://example.com",
        headers={"Host": "example.com"},
    )


def _make_baseline() -> BaselineFingerprint:
    import hashlib
    body = "<html>default</html>"
    return BaselineFingerprint(
        status_code=200,
        content_length=len(body),
        body_hash=hashlib.sha256(body.encode()).hexdigest(),
        avg_response_time=0.1,
        header_names=frozenset(["content-type"]),
    )


def _make_candidates(count=3) -> list[PayloadCandidate]:
    param = _make_param()
    return [
        PayloadCandidate(
            parameter=param,
            payload=f"payload_{i}",
            attack_class="test_class",
            destructive=False,
        )
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# IRREVERSIBLE_METHODS
# ---------------------------------------------------------------------------

class TestIrreversibleMethods:
    """A5: Verify IRREVERSIBLE_METHODS constant."""

    def test_delete_is_irreversible(self):
        """A5: DELETE must be in IRREVERSIBLE_METHODS."""
        assert "DELETE" in IRREVERSIBLE_METHODS

    def test_get_is_not_irreversible(self):
        """A5: GET must NOT be in IRREVERSIBLE_METHODS."""
        assert "GET" not in IRREVERSIBLE_METHODS

    def test_post_is_not_irreversible(self):
        """A5: POST must NOT be in IRREVERSIBLE_METHODS."""
        assert "POST" not in IRREVERSIBLE_METHODS

    def test_put_is_not_irreversible(self):
        """A5: PUT must NOT be in IRREVERSIBLE_METHODS."""
        assert "PUT" not in IRREVERSIBLE_METHODS

    def test_patch_is_not_irreversible(self):
        """A5: PATCH must NOT be in IRREVERSIBLE_METHODS."""
        assert "PATCH" not in IRREVERSIBLE_METHODS


# ---------------------------------------------------------------------------
# DELETE gate without allow_irreversible_delete
# ---------------------------------------------------------------------------

class TestDeleteGateWithoutAllow:
    """A5: DELETE method without allow_irreversible_delete blocks all payloads."""

    def test_delete_blocks_payloads_without_allow_flag(self):
        """A5: DELETE endpoint without flag → _fire_single returns gate-blocked result."""
        req = _make_req(method="DELETE")
        baseline = _make_baseline()
        candidates = _make_candidates()

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            allow_irreversible_delete=False,
        )

        # All candidates should be marked destructive and non-restorable
        for c in candidates:
            assert c.destructive is True, "DELETE payloads should be marked destructive"
            assert c.destructive_reason == "method=DELETE is irreversible"
            assert c.restorable is False, "DELETE payloads should be non-restorable"

        # _fire_single should block (status_code=0, hit=False)
        # We mock the runner.send to verify it's never called
        loop.runner.send = AsyncMock(return_value=MagicMock(
            status_code=200, body="<html>default</html>", headers={}, elapsed=0.1
        ))

        async def _test():
            result = await loop._fire_single(candidates[0])
            assert result.status_code == 0, "Gate-blocked payload should have status_code=0"
            assert result.hit is False
            assert loop.runner.send.call_count == 0, "send() should never be called"

        import asyncio
        asyncio.run(_test())


# ---------------------------------------------------------------------------
# DELETE gate with allow_irreversible_delete
# ---------------------------------------------------------------------------

class TestDeleteGateWithAllow:
    """A5: DELETE method with allow_irreversible_delete allows payloads."""

    def test_delete_allows_payloads_with_allow_flag(self):
        """A5: DELETE endpoint with flag → _fire_single fires payload."""
        req = _make_req(method="DELETE")
        baseline = _make_baseline()
        candidates = _make_candidates()

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            allow_irreversible_delete=True,
        )

        # Candidates should still be marked destructive and non-restorable
        for c in candidates:
            assert c.destructive is True
            assert c.restorable is False

        # But _fire_single should allow firing
        loop.runner.send = AsyncMock(return_value=MagicMock(
            status_code=200, body="<html>default</html>", headers={}, elapsed=0.1
        ))

        async def _test():
            result = await loop._fire_single(candidates[0])
            assert result.status_code == 200, "Payload should be fired"
            assert result.hit is False
            assert loop.runner.send.call_count == 1, "send() should be called once"

        import asyncio
        asyncio.run(_test())


# ---------------------------------------------------------------------------
# Non-irreversible methods
# ---------------------------------------------------------------------------

class TestNonIrreversibleMethods:
    """A5: GET/POST/PUT/PATCH don't trigger the irreversible gate."""

    def test_get_does_not_mark_destructive(self):
        """A5: GET endpoint doesn't mark payloads as destructive."""
        req = _make_req(method="GET")
        baseline = _make_baseline()
        candidates = _make_candidates()

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            allow_irreversible_delete=True,  # doesn't matter for GET
        )

        for c in candidates:
            assert c.destructive is False, "GET payloads should not be marked destructive"
            assert c.restorable is True, "GET payloads should be restorable"

    def test_post_does_not_mark_destructive(self):
        """A5: POST endpoint doesn't mark payloads as destructive."""
        req = _make_req(method="POST")
        baseline = _make_baseline()
        candidates = _make_candidates()

        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
            allow_irreversible_delete=True,
        )

        for c in candidates:
            assert c.destructive is False
            assert c.restorable is True


# ---------------------------------------------------------------------------
# Explicit allow_irreversible_delete flag required
# ---------------------------------------------------------------------------

class TestExplicitFlagRequired:
    """A5: DELETE endpoints require explicit --allow-irreversible-delete flag."""

    def test_default_is_no_allow(self):
        """A5: Without explicit flag, DELETE is blocked (default False)."""
        req = _make_req(method="DELETE")
        baseline = _make_baseline()
        candidates = _make_candidates()

        # Don't pass allow_irreversible_delete — should default to False
        loop = PayloadLoop(
            request_model=req,
            baseline_fingerprint=baseline,
            payloads=candidates,
        )

        # Candidates should be marked destructive and non-restorable
        for c in candidates:
            assert c.destructive is True
            assert c.restorable is False
            assert c.destructive_reason == "method=DELETE is irreversible"

    def test_logger_warning_when_delete_no_allow(self):
        """A5: Logger.warning is called when DELETE detected without allow flag."""
        req = _make_req(method="DELETE")
        baseline = _make_baseline()
        candidates = _make_candidates()

        with patch("nagapasha.engine.payload_loop.logger") as mock_logger:
            PayloadLoop(
                request_model=req,
                baseline_fingerprint=baseline,
                payloads=candidates,
                allow_irreversible_delete=False,
            )
            # Should have called warning at least once
            assert mock_logger.warning.called, "Expected warning about DELETE without allow flag"
            warning_msg = mock_logger.warning.call_args[0][0]
            assert "DELETE" in warning_msg
            assert "allow_irreversible_delete" in warning_msg
