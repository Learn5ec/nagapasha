"""Tests for the cURL parser (Stage 1)."""

import pytest
from nagapasha.stages.stage01_parse import (
    parse_curl,
    CurlParseError,
    infer_type,
    is_auth_param,
    parse_url,
    parse_cookies,
    detect_body_type,
)
from nagapasha.models.request_model import ParameterModel


# ---------------------------------------------------------------------------
# Type inference
# ---------------------------------------------------------------------------


class TestInferType:
    def test_integer(self):
        assert infer_type("42") == "int"
        assert infer_type("-1") == "int"
        assert infer_type("0") == "int"

    def test_uuid(self):
        uid = "550e8400-e29b-41d4-a716-446655440000"
        assert infer_type(uid) == "uuid"

    def test_email(self):
        assert infer_type("user@example.com") == "email"

    def test_filename(self):
        assert infer_type("photo.jpg") == "filename"
        assert infer_type("document.PDF") == "filename"
        assert infer_type("archive.zip") == "filename"

    def test_date(self):
        assert infer_type("2024-01-15") == "date"
        assert infer_type("2024-12-31") == "date"

    def test_boolean(self):
        assert infer_type("true") == "boolean"
        assert infer_type("FALSE") == "boolean"
        assert infer_type("yes") == "boolean"
        assert infer_type("no") == "boolean"

    def test_free_text(self):
        assert infer_type("hello world") == "free_text"
        assert infer_type("search-query-here") == "free_text"
        assert infer_type("abc123xyz") == "free_text"


# ---------------------------------------------------------------------------
# Auth param detection
# ---------------------------------------------------------------------------


class TestIsAuthParam:
    def test_auth_headers(self):
        assert is_auth_param("authorization") is True
        assert is_auth_param("x-auth-token") is True
        assert is_auth_param("x-api-key") is True

    def test_non_auth(self):
        assert is_auth_param("content-type") is False
        assert is_auth_param("user-agent") is False
        assert is_auth_param("accept") is False


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------


class TestParseUrl:
    def test_simple(self):
        base, segments, params = parse_url("https://api.example.com/users?page=1")
        assert base == "https://api.example.com"
        assert segments == ["users"]
        assert params == {"page": "1"}

    def test_nested_path(self):
        base, segments, params = parse_url(
            "https://example.com/api/v1/users/123/items"
        )
        assert base == "https://example.com"
        assert segments == ["api", "v1", "users", "123", "items"]
        assert params == {}

    def test_empty_query(self):
        base, segments, params = parse_url("https://example.com/path")
        assert base == "https://example.com"
        assert segments == ["path"]
        assert params == {}


# ---------------------------------------------------------------------------
# Cookie parsing
# ---------------------------------------------------------------------------


class TestParseCookies:
    def test_single(self):
        assert parse_cookies("session=abc123") == {"session": "abc123"}

    def test_multiple(self):
        result = parse_cookies("a=1; b=2; c=3")
        assert result == {"a": "1", "b": "2", "c": "3"}

    def test_empty(self):
        assert parse_cookies("") == {}
        assert parse_cookies(None) == {}


# ---------------------------------------------------------------------------
# Body type detection
# ---------------------------------------------------------------------------


class TestDetectBodyType:
    def test_json(self):
        assert detect_body_type('{"key": "value"}') == "json"
        assert detect_body_type('[1, 2, 3]') == "json"

    def test_form(self):
        assert detect_body_type("key1=value1&key2=value2") == "form"

    def test_raw(self):
        assert detect_body_type("plain text body") == "raw"
        assert detect_body_type("random stuff") == "raw"

    def test_multipart(self):
        assert detect_body_type("--boundary\ncontent") == "multipart"


# ---------------------------------------------------------------------------
# Full curl parsing
# ---------------------------------------------------------------------------


class TestParseCurl:
    def test_simple_get(self):
        req = parse_curl("curl -X GET 'https://example.com/api/test'")
        assert req.method == "GET"
        assert "example.com" in req.url
        assert req.base_url == "https://example.com"
        assert len(req.parameters) > 0  # at least path params

    def test_get_with_query_params(self):
        req = parse_curl(
            "curl -X GET 'https://api.example.com/users?page=1&limit=10'"
        )
        assert req.method == "GET"
        params = {p.name: p for p in req.parameters}
        assert "page" in params
        assert params["page"].inferred_type == "int"
        assert params["limit"].inferred_type == "int"

    def test_post_with_json_body(self):
        req = parse_curl(
            "curl -X POST 'https://api.example.com/users' "
            "-H 'Content-Type: application/json' "
            "-d '{\"name\": \"test\", \"age\": 30}'"
        )
        assert req.method == "POST"
        assert req.body_type == "json"
        assert req.body is not None
        params = {p.name: p for p in req.parameters}
        assert "name" in params
        assert "age" in params

    def test_with_headers(self):
        req = parse_curl(
            "curl -X GET 'https://example.com' "
            "-H 'X-Custom: value1' "
            "-H 'Accept: application/json'"
        )
        assert req.headers.get("X-Custom") == "value1"
        assert req.headers.get("Accept") == "application/json"

    def test_with_cookies(self):
        req = parse_curl(
            "curl -X GET 'https://example.com' "
            "-b 'session=abc123; user=john'"
        )
        assert req.cookies.get("session") == "abc123"
        assert req.cookies.get("user") == "john"

    def test_with_auth(self):
        req = parse_curl(
            "curl -X GET 'https://example.com' "
            "-u 'user:password'"
        )
        assert "Authorization" in req.headers

    def test_with_data_urlencode(self):
        req = parse_curl(
            "curl -X POST 'https://example.com' "
            "--data-urlencode 'search=hello world'"
        )
        assert req.body is not None or "search" in str(req.query_params)

    def test_invalid_command(self):
        with pytest.raises(CurlParseError):
            parse_curl("echo 'hello world'")

    def test_no_url(self):
        with pytest.raises(CurlParseError):
            parse_curl("curl -X GET")

    def test_basic_auth_header(self):
        req = parse_curl(
            "curl 'https://example.com' -u 'admin:secret123'"
        )
        assert "Authorization" in req.headers
        assert req.headers["Authorization"].startswith("Basic ")


# ---------------------------------------------------------------------------
# ParameterModel roundtrip
# ---------------------------------------------------------------------------


class TestParameterModel:
    def test_to_dict(self):
        p = ParameterModel(
            name="test",
            location="query",
            inferred_type="int",
            raw_value="42",
        )
        d = p.to_dict()
        assert d["name"] == "test"
        assert d["location"] == "query"
        assert d["inferred_type"] == "int"

    def test_from_dict(self):
        p = ParameterModel.from_dict({
            "name": "test",
            "location": "header",
            "inferred_type": "free_text",
            "raw_value": "abc",
        })
        assert p.name == "test"
        assert p.location == "header"
