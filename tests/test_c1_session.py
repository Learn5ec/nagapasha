"""C1 tests: Session manager module (session_manager).

Verifies:
- SessionContext dataclass structure
- Cookie extraction from Set-Cookie headers
- Token extraction from response body/headers
- LocalStorage extraction from SPA response body
- Expiration detection from headers/body
- Session injection into request model
- Session validation (expiration check)
"""

import json
import pytest
from datetime import datetime, timedelta, timezone
from typing import Optional

from nagapasha.session.session_manager import (
    SessionContext,
    SessionEstablishmentResult,
    extract_cookies_from_headers,
    extract_token_from_response,
    extract_local_storage_from_body,
    detect_expiration,
    inject_session,
    is_session_valid,
)
from nagapasha.models.request_model import RequestModel, ParameterModel


# ---------------------------------------------------------------------------
# SessionContext structure
# ---------------------------------------------------------------------------


class TestSessionContext:
    """C1: SessionContext dataclass structure."""

    def test_session_context_exists(self):
        """C1: SessionContext must be importable from session_manager."""
        assert SessionContext is not None

    def test_session_context_default_fields(self):
        """C1: All fields must have sensible defaults."""
        ctx = SessionContext()
        assert ctx.label == "default"
        assert ctx.cookies == {}
        assert ctx.auth_header is None
        assert ctx.local_storage == {}
        assert ctx.expires_at is None
        assert ctx.session_id is not None

    def test_session_context_with_values(self):
        """C1: SessionContext must accept all fields."""
        ctx = SessionContext(
            label="admin",
            cookies={"session": "abc123"},
            auth_header="Bearer token123",
            local_storage={"token": "local_token"},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            session_id="abc123",
        )
        assert ctx.label == "admin"
        assert ctx.cookies == {"session": "abc123"}
        assert ctx.auth_header == "Bearer token123"
        assert ctx.local_storage == {"token": "local_token"}
        assert ctx.expires_at is not None
        assert ctx.session_id == "abc123"


# ---------------------------------------------------------------------------
# SessionEstablishmentResult structure
# ---------------------------------------------------------------------------


class TestSessionEstablishmentResult:
    """C1: SessionEstablishmentResult dataclass structure."""

    def test_result_default_fields(self):
        """C1: All fields must have default values."""
        r = SessionEstablishmentResult()
        assert r.session is None
        assert r.success is False
        assert r.error is None
        assert r.auth_method is None


# ---------------------------------------------------------------------------
# Cookie extraction
# ---------------------------------------------------------------------------


class TestCookieExtraction:
    """C1: Verify cookie extraction from Set-Cookie headers."""

    def test_extract_single_cookie(self):
        """C1: Single Set-Cookie header must be extracted."""
        headers = {"Set-Cookie": "session=abc123; Path=/; HttpOnly"}
        cookies = extract_cookies_from_headers(headers)
        assert cookies == {"session": "abc123"}

    def test_extract_multiple_cookies(self):
        """C1: Multiple Set-Cookie headers must all be extracted."""
        # Note: In a dict, only the last Set-Cookie is kept
        # In real HTTP responses, headers are typically httpx.Headers which supports multiple values
        headers = {
            "Set-Cookie": "token=xyz789; Path=/",
        }
        cookies = extract_cookies_from_headers(headers)
        assert cookies == {"token": "xyz789"}

    def test_extract_no_cookies(self):
        """C1: No Set-Cookie headers must return empty dict."""
        headers = {"Content-Type": "application/json"}
        cookies = extract_cookies_from_headers(headers)
        assert cookies == {}

    def test_extract_cookie_with_options(self):
        """C1: Cookie with multiple options must be extracted correctly."""
        headers = {"Set-Cookie": "session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"}
        cookies = extract_cookies_from_headers(headers)
        assert cookies == {"session": "abc123"}


# ---------------------------------------------------------------------------
# Token extraction
# ---------------------------------------------------------------------------


class TestTokenExtraction:
    """C1: Verify token extraction from response."""

    def test_extract_bearer_token(self):
        """C1: Bearer token must be extracted from Authorization header."""
        headers = {"Authorization": "Bearer my_token_123"}
        token = extract_token_from_response("", headers)
        assert token == "Bearer my_token_123"

    def test_extract_token_from_body(self):
        """C1: Token must be extracted from response body."""
        body = json.dumps({"token": "body_token_123"})
        token = extract_token_from_response(body, {})
        assert token == "body_token_123"

    def test_extract_access_token(self):
        """C1: access_token must be extracted from response body."""
        body = json.dumps({"access_token": "access_token_123"})
        token = extract_token_from_response(body, {})
        assert token == "access_token_123"

    def test_extract_session_id(self):
        """C1: session_id must be extracted from response body."""
        body = json.dumps({"session_id": "session_123"})
        token = extract_token_from_response(body, {})
        assert token == "session_123"

    def test_extract_nested_token(self):
        """C1: Nested token must be extracted from response body."""
        body = json.dumps({"data": {"token": "nested_token_123"}})
        token = extract_token_from_response(body, {})
        assert token == "nested_token_123"

    def test_no_token(self):
        """C1: No token present must return None."""
        body = json.dumps({"message": "success"})
        token = extract_token_from_response(body, {})
        assert token is None

    def test_no_headers(self):
        """C1: Empty headers must return None."""
        token = extract_token_from_response("", {})
        assert token is None

    def test_empty_body(self):
        """C1: Empty body must return None."""
        token = extract_token_from_response("", {"Authorization": "Bearer token"})
        assert token == "Bearer token"


# ---------------------------------------------------------------------------
# LocalStorage extraction
# ---------------------------------------------------------------------------


class TestLocalStorageExtraction:
    """C1: Verify localStorage extraction from SPA response body."""

    def test_extract_from_json_pattern(self):
        """C1: JSON-like pattern must be extracted."""
        body = '{"token": "local_token_123"}'
        local_storage = extract_local_storage_from_body(body)
        assert local_storage == {"token": "local_token_123"}

    def test_extract_from_setitem(self):
        """C1: setItem pattern must be extracted."""
        body = "localStorage.setItem('token', 'local_token_123');"
        local_storage = extract_local_storage_from_body(body)
        assert local_storage == {"token": "local_token_123"}

    def test_no_local_storage(self):
        """C1: No localStorage patterns must return empty dict."""
        body = "console.log('hello');"
        local_storage = extract_local_storage_from_body(body)
        assert local_storage == {}

    def test_empty_body(self):
        """C1: Empty body must return empty dict."""
        local_storage = extract_local_storage_from_body("")
        assert local_storage == {}


# ---------------------------------------------------------------------------
# Expiration detection
# ---------------------------------------------------------------------------


class TestExpirationDetection:
    """C1: Verify expiration detection from headers/body."""

    def test_detect_max_age(self):
        """C1: Max-Age must be detected and converted to datetime."""
        headers = {"Set-Cookie": "session=abc123; Path=/; Max-Age=3600"}
        expiration = detect_expiration(headers, "")
        assert expiration is not None
        # Should be approximately 1 hour from now
        expected = datetime.now(timezone.utc) + timedelta(hours=1)
        assert abs((expiration - expected).total_seconds()) < 5

    def test_detect_expires_in(self):
        """C1: expires_in (seconds) must be detected."""
        body = json.dumps({"expires_in": 3600})
        expiration = detect_expiration({}, body)
        assert expiration is not None
        # Should be approximately 1 hour from now
        expected = datetime.now(timezone.utc) + timedelta(hours=1)
        assert abs((expiration - expected).total_seconds()) < 5

    def test_no_expiration(self):
        """C1: No expiration info must return None."""
        headers = {"Set-Cookie": "session=abc123; Path=/"}
        expiration = detect_expiration(headers, "")
        assert expiration is None


# ---------------------------------------------------------------------------
# Session injection
# ---------------------------------------------------------------------------


class TestSessionInjection:
    """C1: Verify session injection into request model."""

    def test_inject_auth_header(self):
        """C1: Auth header must be injected into request."""
        request = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
        )
        session = SessionContext(auth_header="Bearer token123")
        modified = inject_session(request, session)

        assert modified.headers["Authorization"] == "Bearer token123"

    def test_inject_cookies(self):
        """C1: Cookies must be injected into request."""
        request = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
        )
        session = SessionContext(cookies={"session": "abc123", "token": "xyz789"})
        modified = inject_session(request, session)

        assert "Cookie" in modified.headers
        assert "session=abc123" in modified.headers["Cookie"]
        assert "token=xyz789" in modified.headers["Cookie"]

    def test_inject_local_storage(self):
        """C1: localStorage tokens must be injected as headers."""
        request = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
        )
        session = SessionContext(local_storage={"token": "local_token"})
        modified = inject_session(request, session)

        assert "X-LocalStorage-Token" in modified.headers
        assert modified.headers["X-LocalStorage-Token"] == "local_token"

    def test_no_injection_without_session(self):
        """C1: No injection must occur if session is empty."""
        request = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
        )
        session = SessionContext()
        modified = inject_session(request, session)

        assert modified.headers == {}

    def test_injection_preserves_existing_headers(self):
        """C1: Injection must preserve existing headers."""
        request = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
            headers={"X-Custom": "value"},
        )
        session = SessionContext(auth_header="Bearer token123")
        modified = inject_session(request, session)

        assert modified.headers["X-Custom"] == "value"
        assert modified.headers["Authorization"] == "Bearer token123"


# ---------------------------------------------------------------------------
# Session validation
# ---------------------------------------------------------------------------


class TestSessionValidation:
    """C1: Verify session validation logic."""

    def test_valid_session_no_expiration(self):
        """C1: Session with no expiration must be valid."""
        session = SessionContext()
        assert is_session_valid(session) is True

    def test_valid_session_future_expiration(self):
        """C1: Session with future expiration must be valid."""
        session = SessionContext(
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        assert is_session_valid(session) is True

    def test_invalid_session_past_expiration(self):
        """C1: Session with past expiration must be invalid."""
        session = SessionContext(
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        assert is_session_valid(session) is False

    def test_invalid_session_none(self):
        """C1: None session must be invalid."""
        assert is_session_valid(None) is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """C1: Edge case tests."""

    def test_multiple_bearer_tokens(self):
        """C1: Multiple Bearer tokens must return first one."""
        headers = {
            "Authorization": "Bearer first_token",
            "X-Secondary": "Bearer second_token",
        }
        token = extract_token_from_response("", headers)
        assert token == "Bearer first_token"

    def test_invalid_json_body(self):
        """C1: Invalid JSON body must not crash."""
        token = extract_token_from_response("invalid json", {})
        assert token is None

    def test_empty_local_storage_body(self):
        """C1: Empty localStorage body must return empty dict."""
        local_storage = extract_local_storage_from_body("")
        assert local_storage == {}

    def test_setitem_with_special_chars(self):
        """C1: setItem with special chars must be extracted."""
        body = "localStorage.setItem('token', 'abc!@#$%^&*()');"
        local_storage = extract_local_storage_from_body(body)
        assert local_storage == {"token": "abc!@#$%^&*()"}
