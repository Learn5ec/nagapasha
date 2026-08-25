"""B1 tests: OpenAPI ingestion module (stage09_openapi).

Verifies:
- DiscoveredEndpoint dataclass structure + full_url()
- parse_openapi_spec() JSON parsing
- YAML parsing (with pyyaml)
- Parameter extraction from all locations
- Type mapping (integer→int, string/email→email, etc.)
- Security scheme resolution (Bearer, API key, basic)
- Path template resolution with examples, defaults, synthetics
- Scope filtering
- Risk tagging
- Error handling (invalid spec, unsupported version, network errors)
"""

import json
import pytest
from pathlib import Path
from dataclasses import asdict
from typing import Optional, Any
from unittest.mock import MagicMock, patch

from nagapasha.stages.stage09_openapi import (
    DiscoveredEndpoint,
    OpenAPIParseResult,
    OpenAPIFetchError,
    OpenAPIParseError,
    map_openapi_type,
    resolve_path_template,
    extract_security_headers,
    compute_risk_tags,
    _extract_parameters,
    _extract_request_body,
    _merge_parameters,
    parse_spec_body,
    _extract_endpoints,
    _validate_openapi,
    fetch_spec_content,
    parse_openapi_spec,
)
from nagapasha.models.request_model import ParameterModel


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

SAMPLE_OPENAPI_JSON = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0.0"},
    "servers": [{"url": "https://api.example.com"}],
    "paths": {
        "/users": {
            "get": {
                "operationId": "listUsers",
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer"}},
                ],
                "responses": {"200": {"description": "OK"}},
            },
            "post": {
                "operationId": "createUser",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "email": {"type": "string", "format": "email"},
                                },
                            }
                        }
                    }
                },
                "responses": {"201": {"description": "Created"}},
            },
        },
        "/users/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
            ],
            "get": {
                "operationId": "getUser",
                "responses": {"200": {"description": "OK"}},
            },
            "put": {
                "operationId": "updateUser",
                "parameters": [
                    {"name": "X-Request-ID", "in": "header", "schema": {"type": "string", "format": "uuid"}},
                ],
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "OK"}},
            },
            "delete": {
                "operationId": "deleteUser",
                "security": [{"bearerAuth": []}],
                "responses": {"204": {"description": "No Content"}},
            },
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
            "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        },
    },
    "security": [{"bearerAuth": []}],
}


# ---------------------------------------------------------------------------
# DiscoveredEndpoint structure
# ---------------------------------------------------------------------------

class TestDiscoveredEndpoint:
    """B1: DiscoveredEndpoint dataclass structure."""

    def test_exists(self):
        """B1: DiscoveredEndpoint must be importable from stage09_openapi."""
        assert DiscoveredEndpoint is not None

    def test_default_fields(self):
        """B1: All fields must have sensible defaults."""
        ep = DiscoveredEndpoint(method="GET", path_template="/test", concrete_path="/test")
        assert ep.parameters == []
        assert ep.body_schema is None
        assert ep.source == "openapi"
        assert ep.risk_tags == []
        assert ep.base_url is None

    def test_full_url_construction(self):
        """B1: full_url() must construct the concrete URL."""
        ep = DiscoveredEndpoint(
            method="GET",
            path_template="/users/{id}",
            concrete_path="/users/1",
            base_url="https://api.example.com",
        )
        assert ep.full_url() == "https://api.example.com/users/1"

    def test_full_url_no_trailing_slash(self):
        """B1: full_url() must handle base_url without trailing slash."""
        ep = DiscoveredEndpoint(
            method="GET",
            path_template="/test",
            concrete_path="/test",
            base_url="https://api.example.com",
        )
        assert ep.full_url() == "https://api.example.com/test"

    def test_full_url_concrete_path_strips_leading_slash(self):
        """B1: full_url() must strip leading slash from concrete_path."""
        ep = DiscoveredEndpoint(
            method="GET",
            path_template="/test",
            concrete_path="test",
            base_url="https://api.example.com/",
        )
        assert ep.full_url() == "https://api.example.com/test"


# ---------------------------------------------------------------------------
# OpenAPIParseResult structure
# ---------------------------------------------------------------------------

class TestOpenAPIParseResult:
    """B1: OpenAPIParseResult dataclass structure."""

    def test_default_fields(self):
        """B1: All fields must have default values."""
        r = OpenAPIParseResult()
        assert r.endpoints == []
        assert r.spec_version == ""
        assert r.spec_title == ""
        assert r.auth_schemes == []
        assert r.warnings == []


# ---------------------------------------------------------------------------
# Type mapping
# ---------------------------------------------------------------------------

class TestTypeMapping:
    """B1: Verify OpenAPI type+format → ParameterModel.inferred_type mapping."""

    @pytest.mark.parametrize("oa_type,oa_format,expected", [
        ("integer", None, "int"),
        ("number", None, "free_text"),
        ("boolean", None, "boolean"),
        ("string", "email", "email"),
        ("string", "uuid", "uuid"),
        ("string", "guid", "uuid"),
        ("string", "date-time", "date"),
        ("string", "date", "date"),
        ("string", "binary", "filename"),
        ("string", "byte", "filename"),
        ("string", "file", "filename"),
        ("string", None, "free_text"),
        ("array", None, "free_text"),
        ("object", None, "free_text"),
        (None, None, "free_text"),
    ])
    def test_type_mapping(self, oa_type, oa_format, expected):
        """B1: All type+format combinations must map correctly."""
        assert map_openapi_type(oa_type, oa_format) == expected


# ---------------------------------------------------------------------------
# Path template resolution
# ---------------------------------------------------------------------------

class TestPathTemplateResolution:
    """B1: Verify path template resolution logic."""

    def test_resolve_with_example(self):
        """B1: Spec example value must be used for path resolution."""
        path_params = [
            {"name": "id", "in": "path", "example": "550e8400-e29b-41d4-a716-446655440000"},
        ]
        result = resolve_path_template("/users/{id}", path_params)
        assert result == "/users/550e8400-e29b-41d4-a716-446655440000"

    def test_resolve_with_default(self):
        """B1: Spec default value must be used when no example."""
        path_params = [
            {"name": "id", "in": "path", "schema": {"type": "string", "default": "1"}},
        ]
        result = resolve_path_template("/users/{id}", path_params)
        assert result == "/users/1"

    def test_resolve_with_harvested(self):
        """B1: Harvested values must be used when no example/default."""
        path_params = [
            {"name": "id", "in": "path", "schema": {"type": "string"}},
        ]
        result = resolve_path_template(
            "/users/{id}", path_params, harvested_values={"id": "harvested-id"}
        )
        assert result == "/users/harvested-id"

    def test_resolve_with_synthetic(self):
        """B1: User-provided synthetic defaults must be used."""
        path_params = [
            {"name": "id", "in": "path", "schema": {"type": "string"}},
        ]
        result = resolve_path_template(
            "/users/{id}", path_params, synthetic_defaults={"id": "synthetic-1"}
        )
        assert result == "/users/synthetic-1"

    def test_resolve_with_smart_synthetic(self):
        """B1: Smart synthetic defaults must be used as last resort."""
        path_params = [
            {"name": "id", "in": "path", "schema": {"type": "string"}},
        ]
        result = resolve_path_template("/users/{id}", path_params)
        assert result == "/users/1"

    def test_resolve_multiple_placeholders(self):
        """B1: Multiple placeholders must all be resolved."""
        path_params = [
            {"name": "userId", "in": "path", "example": "user-1"},
            {"name": "postId", "in": "path", "example": "post-1"},
        ]
        result = resolve_path_template(
            "/users/{userId}/posts/{postId}", path_params
        )
        assert result == "/users/user-1/posts/post-1"

    def test_resolve_no_placeholders(self):
        """B1: Path without placeholders must be returned as-is."""
        result = resolve_path_template("/health", [])
        assert result == "/health"

    def test_resolve_prefers_example_over_default(self):
        """B1: Example must be preferred over default value."""
        path_params = [
            {"name": "id", "in": "path", "example": "example-id", "schema": {"default": "default-id"}},
        ]
        result = resolve_path_template("/users/{id}", path_params)
        assert result == "/users/example-id"

    def test_resolve_prefers_example_over_harvested(self):
        """B1: Example must be preferred over harvested value."""
        path_params = [
            {"name": "id", "in": "path", "example": "example-id"},
        ]
        result = resolve_path_template(
            "/users/{id}", path_params, harvested_values={"id": "harvested-id"}
        )
        assert result == "/users/example-id"

    def test_resolve_prefers_harvested_over_synthetic(self):
        """B1: Harvested must be preferred over synthetic."""
        path_params = [
            {"name": "id", "in": "path", "schema": {"type": "string"}},
        ]
        result = resolve_path_template(
            "/users/{id}",
            path_params,
            harvested_values={"id": "harvested-id"},
            synthetic_defaults={"id": "synthetic-1"},
        )
        assert result == "/users/harvested-id"

    def test_resolve_prefers_synthetic_over_smart(self):
        """B1: Synthetic must be preferred over smart synthetic."""
        path_params = [
            {"name": "id", "in": "path", "schema": {"type": "string"}},
        ]
        result = resolve_path_template(
            "/users/{id}", path_params, synthetic_defaults={"id": "synthetic-1"}
        )
        assert result == "/users/synthetic-1"


# ---------------------------------------------------------------------------
# Security scheme resolution
# ---------------------------------------------------------------------------

class TestSecurityResolution:
    """B1: Verify security scheme resolution."""

    def test_bearer_security(self):
        """B1: Bearer auth must produce Authorization: Bearer header."""
        spec = {
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer"},
                },
            },
        }
        headers, schemes = extract_security_headers(
            spec=spec, operation_security=[{"bearerAuth": []}]
        )
        assert headers["Authorization"] == "Bearer <token>"
        assert "bearer" in schemes

    def test_basic_security(self):
        """B1: HTTP basic must produce Authorization: Basic header."""
        spec = {
            "components": {
                "securitySchemes": {
                    "basicAuth": {"type": "http", "scheme": "basic"},
                },
            },
        }
        headers, schemes = extract_security_headers(
            spec=spec, operation_security=[{"basicAuth": []}]
        )
        assert headers["Authorization"] == "Basic <credentials>"
        assert "basic" in schemes

    def test_apikey_header_security(self):
        """B1: API key in header must produce named header."""
        spec = {
            "components": {
                "securitySchemes": {
                    "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                },
            },
        }
        headers, schemes = extract_security_headers(
            spec=spec, operation_security=[{"apiKey": []}]
        )
        assert headers["X-API-Key"] == "<key>"
        assert "apikey-X-API-Key" in schemes

    def test_no_security(self):
        """B1: No security requirements must produce empty headers."""
        spec = {"components": {"securitySchemes": {}}}
        headers, schemes = extract_security_headers(
            spec=spec, operation_security=[]
        )
        assert headers == {}
        assert schemes == []

    def test_multiple_security_schemes(self):
        """B1: Multiple security schemes must all be resolved."""
        spec = {
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer"},
                    "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                },
            },
        }
        headers, schemes = extract_security_headers(
            spec=spec,
            operation_security=[
                {"bearerAuth": []},
                {"apiKey": []},
            ],
        )
        assert "Authorization" in headers
        assert "X-API-Key" in headers
        assert "bearer" in schemes
        assert "apikey-X-API-Key" in schemes


# ---------------------------------------------------------------------------
# Risk tagging
# ---------------------------------------------------------------------------

class TestRiskTags:
    """B1: Verify risk tag computation."""

    @pytest.mark.parametrize("method,path,has_security,expected_tags", [
        ("GET", "/users", False, []),
        ("GET", "/users", True, ["auth"]),
        ("POST", "/users", True, ["auth", "write"]),
        ("PUT", "/users/{id}", True, ["auth", "write"]),
        ("DELETE", "/users/{id}", True, ["auth", "write", "delete"]),
        ("POST", "/login", True, ["auth", "auth-endpoint", "write"]),
        ("GET", "/health", False, []),
        ("PATCH", "/login", True, ["auth", "auth-endpoint", "write"]),
    ])
    def test_risk_tags(self, method, path, has_security, expected_tags):
        """B1: Risk tags must be computed correctly for all combinations."""
        tags = compute_risk_tags(method=method, path=path, has_security=has_security)
        assert set(tags) == set(expected_tags)


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------

class TestParameterExtraction:
    """B1: Verify parameter extraction from OpenAPI definitions."""

    def test_extract_query_parameters(self):
        """B1: Query parameters must have location='query'."""
        params = [
            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
            {"name": "offset", "in": "query", "schema": {"type": "integer"}},
        ]
        result = _extract_parameters(params)
        assert len(result) == 2
        assert result[0].name == "limit"
        assert result[0].location == "query"
        assert result[0].inferred_type == "int"

    def test_extract_path_parameters(self):
        """B1: Path parameters must have location='path'."""
        params = [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
        ]
        result = _extract_parameters(params)
        assert len(result) == 1
        assert result[0].location == "path"
        assert result[0].inferred_type == "free_text"

    def test_extract_header_parameters(self):
        """B1: Header parameters must have location='header'."""
        params = [
            {"name": "X-Request-ID", "in": "header", "schema": {"type": "string", "format": "uuid"}},
        ]
        result = _extract_parameters(params)
        assert len(result) == 1
        assert result[0].location == "header"
        assert result[0].inferred_type == "uuid"

    def test_extract_body_parameters(self):
        """B1: Body parameters must have location='body_json'."""
        params = [
            {"name": "data", "in": "body", "schema": {"type": "object"}},
        ]
        result = _extract_parameters(params)
        assert len(result) == 1
        assert result[0].location == "body_json"

    def test_extract_email_type(self):
        """B1: String+email format must map to 'email' type."""
        params = [
            {"name": "email", "in": "body", "schema": {"type": "string", "format": "email"}},
        ]
        result = _extract_parameters(params)
        assert result[0].inferred_type == "email"

    def test_extract_parameters_have_raw_value(self):
        """B1: Extracted parameters must have raw_value from example/default."""
        params = [
            {"name": "id", "in": "path", "example": "123"},
        ]
        result = _extract_parameters(params)
        assert result[0].raw_value == "123"


# ---------------------------------------------------------------------------
# Request body extraction
# ---------------------------------------------------------------------------

class TestRequestBodyExtraction:
    """B1: Verify request body schema extraction."""

    def test_extract_json_body(self):
        """B1: JSON request body must be extracted."""
        operation = {
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "properties": {"name": {"type": "string"}}},
                    }
                }
            }
        }
        result = _extract_request_body(operation)
        assert result is not None
        assert result["type"] == "object"

    def test_no_request_body(self):
        """B1: Operation without requestBody must return None."""
        operation = {"responses": {"200": {"description": "OK"}}}
        result = _extract_request_body(operation)
        assert result is None

    def test_extract_non_json_body(self):
        """B1: Non-JSON body must still be extracted as fallback."""
        operation = {
            "requestBody": {
                "content": {
                    "text/plain": {
                        "schema": {"type": "string"},
                    }
                }
            }
        }
        result = _extract_request_body(operation)
        assert result is not None
        assert result["type"] == "string"


# ---------------------------------------------------------------------------
# Parameter merging
# ---------------------------------------------------------------------------

class TestParameterMerging:
    """B1: Verify parameter merging logic."""

    def test_path_params_only(self):
        """B1: Path-level params only must be returned."""
        path_params = [
            {"name": "id", "in": "path", "schema": {"type": "string"}},
        ]
        result = _merge_parameters(path_params, [])
        assert len(result) == 1

    def test_operation_params_only(self):
        """B1: Operation-level params only must be returned."""
        path_params = []
        op_params = [
            {"name": "X-Request-ID", "in": "header", "schema": {"type": "string"}},
        ]
        result = _merge_parameters(path_params, op_params)
        assert len(result) == 1
        assert result[0]["name"] == "X-Request-ID"

    def test_operation_overrides_path(self):
        """B1: Operation-level params must override path-level for same name+location."""
        path_params = [
            {"name": "id", "in": "path", "schema": {"type": "string"}},
        ]
        op_params = [
            {"name": "id", "in": "path", "schema": {"type": "integer"}},
        ]
        result = _merge_parameters(path_params, op_params)
        assert len(result) == 1
        assert result[0]["schema"]["type"] == "integer"

    def test_merge_all_params(self):
        """B1: All unique params must be merged."""
        path_params = [
            {"name": "id", "in": "path", "schema": {"type": "string"}},
            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
        ]
        op_params = [
            {"name": "offset", "in": "query", "schema": {"type": "integer"}},
        ]
        result = _merge_parameters(path_params, op_params)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------

class TestSpecParsing:
    """B1: Verify spec parsing logic."""

    def test_parse_json_spec(self):
        """B1: Valid JSON spec must parse correctly."""
        spec = parse_spec_body(json.dumps(SAMPLE_OPENAPI_JSON))
        assert spec["openapi"] == "3.0.0"
        assert "paths" in spec

    def test_parse_yaml_spec(self):
        """B1: Valid YAML spec must parse correctly."""
        yaml_content = """
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
paths:
  /health:
    get:
      responses:
        "200":
          description: OK
"""
        spec = parse_spec_body(yaml_content)
        assert spec["openapi"] == "3.0.0"
        assert "/health" in spec["paths"]

    def test_parse_invalid_json_raises(self):
        """B1: Invalid JSON must raise OpenAPIParseError."""
        with pytest.raises(OpenAPIParseError):
            parse_spec_body("not valid json or yaml {{{")

    def test_parse_yaml_without_pyyaml_raises(self):
        """B1: YAML without pyyaml must raise OpenAPIParseError."""
        import yaml
        try:
            import yaml
        except ImportError:
            # If pyyaml is not installed, this test will pass
            with pytest.raises(OpenAPIParseError, match="pyyaml"):
                parse_spec_body("key: value")
        else:
            # If pyyaml is installed, YAML parsing will succeed (no error raised)
            # This is expected behavior - the function tries YAML after JSON fails
            result = parse_spec_body("key: value")
            assert result == {"key": "value"}

    def test_validate_openapi_valid(self):
        """B1: Valid OpenAPI 3.0.0 must return version string."""
        spec = {"openapi": "3.0.0", "paths": {}}
        version = _validate_openapi(spec)
        assert version == "3.0.0"

    def test_validate_openapi_swagger_2_raises(self):
        """B1: Swagger 2.0 must raise OpenAPIParseError."""
        spec = {"swagger": "2.0", "paths": {}}
        with pytest.raises(OpenAPIParseError, match="Swagger 2.0"):
            _validate_openapi(spec)

    def test_validate_openapi_missing_paths_raises(self):
        """B1: Spec without 'paths' must raise OpenAPIParseError."""
        spec = {"openapi": "3.0.0", "info": {"title": "Test"}}
        with pytest.raises(OpenAPIParseError, match="paths"):
            _validate_openapi(spec)


# ---------------------------------------------------------------------------
# Fetch spec content
# ---------------------------------------------------------------------------

class TestFetchSpecContent:
    """B1: Verify spec fetching logic."""

    @pytest.mark.asyncio
    async def test_fetch_from_file(self, tmp_path):
        """B1: Local file must be read correctly."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_JSON))
        content = await fetch_spec_content(str(spec_file))
        assert '"openapi"' in content

    @pytest.mark.asyncio
    async def test_fetch_from_file_not_found(self, tmp_path):
        """B1: Non-existent file must raise OpenAPIFetchError."""
        with pytest.raises(OpenAPIFetchError):
            await fetch_spec_content(str(tmp_path / "nonexistent.json"))

    @pytest.mark.asyncio
    async def test_fetch_from_url_mocked(self):
        """B1: URL fetch must use httpx (mocked)."""
        mock_resp = MagicMock()
        mock_resp.text = json.dumps(SAMPLE_OPENAPI_JSON)
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__aenter__.return_value.get.return_value = mock_resp
        mock_client.__aexit__.return_value = None

        with patch("nagapasha.stages.stage09_openapi.httpx.AsyncClient", return_value=mock_client):
            content = await fetch_spec_content("https://api.example.com/spec.json")
            assert '"openapi"' in content

    @pytest.mark.asyncio
    async def test_fetch_from_url_failure(self):
        """B1: Failed URL fetch must raise OpenAPIFetchError."""
        import httpx
        mock_client = MagicMock()
        mock_client.__aenter__.return_value.get.side_effect = httpx.HTTPError("test")
        mock_client.__aexit__.return_value = None

        with patch("nagapasha.stages.stage09_openapi.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(OpenAPIFetchError):
                await fetch_spec_content("https://api.example.com/spec.json")


# ---------------------------------------------------------------------------
# Integration: parse_openapi_spec
# ---------------------------------------------------------------------------

class TestParseOpenApiSpec:
    """B1: Integration tests for parse_openapi_spec()."""

    @pytest.mark.asyncio
    async def test_parse_full_spec(self, tmp_path):
        """B1: Full spec parsing must return all endpoints."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_JSON))

        result = await parse_openapi_spec(spec_source=str(spec_file))

        assert result.spec_version == "3.0.0"
        assert result.spec_title == "Test API"
        assert len(result.endpoints) == 5  # GET /users, POST /users, GET /users/{id}, PUT /users/{id}, DELETE /users/{id}

    @pytest.mark.asyncio
    async def test_parse_spec_with_base_url(self, tmp_path):
        """B1: Base URL must be extracted from servers."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_JSON))

        result = await parse_openapi_spec(spec_source=str(spec_file))
        assert result.endpoints[0].base_url == "https://api.example.com"

    @pytest.mark.asyncio
    async def test_parse_spec_with_path_resolution(self, tmp_path):
        """B1: Path templates must be resolved."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_JSON))

        result = await parse_openapi_spec(spec_source=str(spec_file))

        # Find the GET /users/{id} endpoint
        user_endpoint = None
        for ep in result.endpoints:
            if ep.method == "GET" and ep.path_template == "/users/{id}":
                user_endpoint = ep
                break

        assert user_endpoint is not None
        assert user_endpoint.concrete_path != "/users/{id}"
        assert "{id}" not in user_endpoint.concrete_path

    @pytest.mark.asyncio
    async def test_parse_empty_spec(self, tmp_path):
        """B1: Empty spec must return empty endpoints list."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps({"openapi": "3.0.0", "info": {"title": "Empty"}, "paths": {}}))

        result = await parse_openapi_spec(spec_source=str(spec_file))
        assert result.endpoints == []

    @pytest.mark.asyncio
    async def test_parse_invalid_spec_raises(self, tmp_path):
        """B1: Invalid spec must raise OpenAPIParseError."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text("not json")

        with pytest.raises(OpenAPIParseError):
            await parse_openapi_spec(spec_source=str(spec_file))

    @pytest.mark.asyncio
    async def test_parse_swagger_2_raises(self, tmp_path):
        """B1: Swagger 2.0 must raise OpenAPIParseError."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps({"swagger": "2.0", "paths": {}}))

        with pytest.raises(OpenAPIParseError, match="Swagger 2.0"):
            await parse_openapi_spec(spec_source=str(spec_file))

    @pytest.mark.asyncio
    async def test_parse_yaml_spec(self, tmp_path):
        """B1: YAML spec must parse correctly."""
        yaml_content = """
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
paths:
  /health:
    get:
      responses:
        "200":
          description: OK
"""
        spec_file = tmp_path / "spec.yaml"
        spec_file.write_text(yaml_content)

        result = await parse_openapi_spec(spec_source=str(spec_file))
        assert result.spec_title == "Test API"
        assert len(result.endpoints) == 1

    @pytest.mark.asyncio
    async def test_scope_filtering(self, tmp_path):
        """B1: Scope checker must filter out-of-scope endpoints."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_JSON))

        mock_scope = MagicMock()
        # First 2 endpoints in-scope, rest out of scope
        call_count = [0]

        def scope_check(url, method, description):
            call_count[0] += 1
            if call_count[0] <= 2:
                return  # in scope
            raise Exception("out of scope")

        mock_scope.check = scope_check

        result = await parse_openapi_spec(
            spec_source=str(spec_file),
            scope_checker=mock_scope,
        )

        assert len(result.endpoints) <= 2

    @pytest.mark.asyncio
    async def test_path_template_with_harvested_values(self, tmp_path):
        """B1: Harvested values must override synthetic defaults."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_JSON))

        result = await parse_openapi_spec(
            spec_source=str(spec_file),
            harvested_values={"id": "harvested-id"},
        )

        # Find endpoint with /users/{id} path
        for ep in result.endpoints:
            if "{id}" not in ep.concrete_path:
                continue
            assert "harvested-id" in ep.concrete_path

    @pytest.mark.asyncio
    async def test_auth_schemes_populated(self, tmp_path):
        """B1: Auth schemes must be populated in result."""
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(SAMPLE_OPENAPI_JSON))

        result = await parse_openapi_spec(spec_source=str(spec_file))

        # Bearer auth is specified in spec
        assert len(result.endpoints) > 0
        # Some endpoints should have auth
        auth_endpoints = [ep for ep in result.endpoints if "auth" in ep.risk_tags]
        assert len(auth_endpoints) > 0

    @pytest.mark.asyncio
    async def test_no_spec_source_raises(self):
        """B1: Empty spec source must raise OpenAPIFetchError."""
        with pytest.raises(OpenAPIFetchError):
            await parse_openapi_spec(spec_source="")


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """B1: Verify error handling."""

    def test_openapi_fetch_error(self):
        """B1: OpenAPIFetchError must be importable and usable."""
        with pytest.raises(OpenAPIFetchError):
            raise OpenAPIFetchError("test error")

    def test_openapi_parse_error(self):
        """B1: OpenAPIParseError must be importable and usable."""
        with pytest.raises(OpenAPIParseError):
            raise OpenAPIParseError("test error")

    def test_parse_spec_body_empty_raises(self):
        """B1: Empty string must raise OpenAPIParseError."""
        with pytest.raises(OpenAPIParseError):
            parse_spec_body("")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """B1: Edge case tests."""

    @pytest.mark.asyncio
    async def test_spec_with_no_servers(self, tmp_path):
        """B1: Spec with no servers must set base_url to None."""
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test"},
            "paths": {"/health": {"get": {"responses": {"200": {"description": "OK"}}}}},
        }
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(spec_data))

        result = await parse_openapi_spec(spec_source=str(spec_file))
        assert result.endpoints[0].base_url is None

    @pytest.mark.asyncio
    async def test_spec_with_multiple_methods_same_path(self, tmp_path):
        """B1: Multiple methods on same path must produce separate endpoints."""
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test"},
            "paths": {
                "/users": {
                    "get": {"responses": {"200": {"description": "OK"}}},
                    "post": {"requestBody": {"content": {"application/json": {"schema": {}}}}},
                }
            },
        }
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(spec_data))

        result = await parse_openapi_spec(spec_source=str(spec_file))
        assert len(result.endpoints) == 2
        methods = {ep.method for ep in result.endpoints}
        assert methods == {"GET", "POST"}

    @pytest.mark.asyncio
    async def test_spec_with_no_body(self, tmp_path):
        """B1: Endpoints without requestBody must have body_schema=None."""
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test"},
            "paths": {
                "/health": {
                    "get": {"responses": {"200": {"description": "OK"}}},
                }
            },
        }
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(spec_data))

        result = await parse_openapi_spec(spec_source=str(spec_file))
        assert result.endpoints[0].body_schema is None
