"""Tests for JWT detection and watchdog."""

import asyncio
import json
import time

import pytest

from nagapasha.engine.jwt_watchdog import (
    JwtInfo,
    decode_jwt,
    detect_jwts,
    JwtWatchdog,
    _base64url_decode,
)


def _make_jwt(header: dict, payload: dict) -> str:
    """Helper to create a JWT from header and payload dicts."""
    import base64

    def b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    return f"{h}.{p}."


class TestBase64UrlDecode:
    def test_basic(self):
        result = _base64url_decode("SGVsbG8")
        assert result == b"Hello"

    def test_with_padding(self):
        result = _base64url_decode("SGVsbG8gd29ybGQ")
        assert result == b"Hello world"


class TestDecodeJwt:
    def test_valid_jwt(self):
        token = _make_jwt(
            {"alg": "RS256", "typ": "JWT"},
            {"sub": "1234567890", "exp": int(time.time()) + 3600},
        )
        info = decode_jwt(token)
        assert info.is_jwt is True
        assert info.alg == "RS256"
        assert info.exp > time.time()
        assert info.is_expired is False
        assert info.algorithm_flagged is False

    def test_expired_jwt(self):
        token = _make_jwt(
            {"alg": "RS256"},
            {"sub": "1234567890", "exp": int(time.time()) - 100},
        )
        info = decode_jwt(token)
        assert info.is_jwt is True
        assert info.is_expired is True

    def test_none_algorithm(self):
        token = _make_jwt(
            {"alg": "none"},
            {"sub": "1234567890"},
        )
        info = decode_jwt(token)
        assert info.is_jwt is True
        assert info.alg == "none"
        assert info.algorithm_flagged is True
        assert "none" in info.flag_reason.lower()

    def test_weak_algorithm(self):
        token = _make_jwt(
            {"alg": "HS128"},
            {"sub": "1234567890"},
        )
        info = decode_jwt(token)
        assert info.is_jwt is True
        assert info.algorithm_flagged is True

    def test_invalid_jwt(self):
        info = decode_jwt("not.a.jwt")
        # Should still parse (it has 2 dots) but may fail on base64
        # The function handles this gracefully
        assert isinstance(info, JwtInfo)

    def test_empty_string(self):
        info = decode_jwt("")
        assert info.is_jwt is False

    def test_payload_claims(self):
        token = _make_jwt(
            {"alg": "RS256"},
            {"sub": "123", "exp": int(time.time()) + 3600,
             "iat": int(time.time()), "iss": "test"},
        )
        info = decode_jwt(token)
        assert info.payload.get("iss") == "test"
        assert info.issued_at is not None

    def test_to_dict(self):
        token = _make_jwt(
            {"alg": "RS256"},
            {"sub": "123", "exp": int(time.time()) + 3600},
        )
        info = decode_jwt(token)
        d = info.to_dict()
        assert d["is_jwt"] is True
        assert d["alg"] == "RS256"
        assert "time_remaining" in d


class TestDetectJwts:
    def test_bearer_token(self):
        headers = {"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."}
        cookies = {}
        results = detect_jwts(headers, cookies)
        assert len(results) >= 1
        assert any("Bearer" in k for k in results)

    def test_no_jwt(self):
        headers = {"Content-Type": "application/json"}
        cookies = {}
        results = detect_jwts(headers, cookies)
        assert len(results) == 0

    def test_cookie_jwt(self):
        cookies = {"session": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0."}
        results = detect_jwts({}, cookies)
        assert "session" in results


class TestJwtInfo:
    def test_time_remaining_future(self):
        info = JwtInfo(exp=int(time.time()) + 3600)
        assert info.time_remaining > 3500
        assert info.time_remaining < 3601

    def test_time_remaining_expired(self):
        info = JwtInfo(exp=int(time.time()) - 100)
        assert info.time_remaining < 0

    def test_time_remaining_no_exp(self):
        info = JwtInfo(exp=None)
        assert info.time_remaining == float("inf")


class TestJwtWatchdog:
    @pytest.mark.asyncio
    async def test_no_exp_does_not_monitor(self):
        """No expiry to watch — start should return immediately."""
        watchdog = JwtWatchdog(jwt_info=JwtInfo(exp=None))
        await watchdog.start()
        # Should not block since no exp
        await watchdog.cancel()

    @pytest.mark.asyncio
    async def test_far_expiry_does_not_pause(self):
        """Expiry far in the future should not trigger pause."""
        call_count = []

        def on_pause():
            call_count.append(1)

        jwt = JwtInfo(exp=int(time.time()) + 7200)
        watchdog = JwtWatchdog(jwt_info=jwt, on_pause=on_pause)
        await watchdog.start()
        await asyncio.sleep(0.2)
        await watchdog.cancel()
        assert len(call_count) == 0

    @pytest.mark.asyncio
    async def test_near_expiry_triggers_pause(self):
        """Expiry within pause_at should trigger pause."""
        call_count = []

        def on_pause():
            call_count.append(1)

        # Set expiry very close (3 seconds) so it triggers quickly
        jwt = JwtInfo(exp=int(time.time()) + 3)
        watchdog = JwtWatchdog(jwt_info=jwt, pause_at_seconds_before_expiry=1,
                               on_pause=on_pause)
        await watchdog.start()
        await asyncio.sleep(2.5)
        await watchdog.cancel()
        # Should have triggered at least once
        assert len(call_count) >= 1
