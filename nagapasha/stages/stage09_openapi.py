"""Stage 9 — OpenAPI / Swagger ingestion.

Parses OpenAPI 3.x specifications (JSON or YAML, local file or URL) and
produces a list of ``DiscoveredEndpoint`` objects ready for scanning by
Phase A's engine.

Handles:
  - Path extraction with method enumeration
  - Parameter extraction (query, header, cookie, path, body)
  - Type mapping (OpenAPI type+format → ParameterModel.inferred_type)
  - Security scheme resolution (Bearer, API key, HTTP basic)
  - Path template resolution ({id} → sample/synthetic values)
  - Scope filtering via ScopeChecker
  - Risk tagging (auth, write, delete)

The output is a flat list — downstream stages (engine, orchestrator) iterate
it without knowing it came from a spec rather than a curl command.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx

from nagapasha.models.request_model import ParameterModel

from nagapasha.utils.config import get_config

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class OpenAPIFetchError(Exception):
    """Raised when the spec cannot be fetched or read."""


class OpenAPIParseError(Exception):
    """Raised when the spec is malformed or not a recognized OpenAPI version."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class DiscoveredEndpoint:
    """A single endpoint discovered from an OpenAPI spec.

    Attributes:
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, ...)
        path_template: Raw path template (e.g. "/users/{id}")
        concrete_path: Path with placeholders resolved (e.g. "/users/1")
        parameters: Extracted parameters ready for ParameterModel
        body_schema: Raw request body schema dict, or None
        source: Fixed string "openapi" for traceability
        risk_tags: Classification tags for prioritization
        base_url: Server URL from spec (None if no servers defined)
    """

    method: str
    path_template: str
    concrete_path: str
    parameters: list[ParameterModel] = field(default_factory=list)
    body_schema: Optional[dict[str, Any]] = None
    source: str = "openapi"
    risk_tags: list[str] = field(default_factory=list)
    base_url: Optional[str] = None

    def full_url(self) -> str:
        """Build the concrete URL for this endpoint."""
        base = self.base_url or ""
        if not base.endswith("/"):
            base += "/"
        # Remove leading slash from concrete_path to avoid double slashes
        path = self.concrete_path.lstrip("/")
        return f"{base}{path}"


@dataclass
class OpenAPIParseResult:
    """Structured output of parsing an OpenAPI spec.

    Attributes:
        endpoints: Discovered endpoints ready for scanning
        spec_version: OpenAPI version string (e.g. "3.0.0")
        spec_title: Spec title from info block
        auth_schemes: List of resolved auth scheme names
        base_url: Base URL from spec servers (None if no servers defined)
        warnings: Non-fatal issues encountered during parsing
    """

    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    spec_version: str = ""
    spec_title: str = ""
    auth_schemes: list[str] = field(default_factory=list)
    base_url: Optional[str] = None
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Type mapping: OpenAPI type+format → ParameterModel.inferred_type
# ---------------------------------------------------------------------------

_TYPE_MAP: dict[str, dict[str, str]] = {
    "integer": {"int": "int"},
    "number": {"free_text": "free_text"},
    "boolean": {"boolean": "boolean"},
    "string": {
        "email": "email",
        "uuid": "uuid",
        "guid": "uuid",
        "date-time": "date",
        "date": "date",
        "binary": "filename",
        "byte": "filename",
        "file": "filename",
    },
    "array": {"free_text": "free_text"},
}


def map_openapi_type(
    oa_type: str,
    oa_format: Optional[str] = None,
) -> str:
    """Map OpenAPI type+format to ParameterModel.inferred_type.

    Args:
        oa_type: OpenAPI type string (integer, number, string, boolean, array)
        oa_format: Optional OpenAPI format (email, uuid, date-time, ...)

    Returns:
        One of: "int", "uuid", "email", "filename", "date", "boolean", "free_text"
    """
    oa_type = (oa_type or "").lower()
    oa_format = (oa_format or "").lower()

    type_map = _TYPE_MAP.get(oa_type, {})
    if oa_format and oa_format in type_map:
        return type_map[oa_format]

    # Fallback: check format-only mapping for string type
    if oa_type == "string":
        format_map = {
            "email": "email",
            "uuid": "uuid",
            "guid": "uuid",
            "date-time": "date",
            "date": "date",
            "binary": "filename",
            "byte": "filename",
            "file": "filename",
        }
        return format_map.get(oa_format, "free_text")

    if oa_type == "integer":
        return "int"
    if oa_type == "boolean":
        return "boolean"
    return "free_text"


# ---------------------------------------------------------------------------
# Path template resolution
# ---------------------------------------------------------------------------

# Smart synthetic defaults for common parameter name patterns
_SMART_SYNTHEtics: dict[str, str] = {
    "id": "1",
    "user_id": "1",
    "user-id": "1",
    "post_id": "1",
    "comment_id": "1",
    "page": "1",
    "limit": "10",
    "offset": "0",
    "date": "2024-01-01",
    "email": "user@example.com",
    "token": "placeholder-token",
}


def _smart_synthetic(name: str, param_def: dict) -> str:
    """Generate a safe default value based on parameter name/type hints."""
    name_lower = name.lower()
    if name_lower in _SMART_SYNTHEtics:
        return _SMART_SYNTHEtics[name_lower]

    # Check param schema for type hints
    schema = param_def.get("schema", {})
    if schema:
        oa_type = schema.get("type", "")
        if oa_type == "integer":
            return "1"
        if oa_type == "string":
            oa_format = schema.get("format", "")
            if oa_format == "uuid":
                return "550e8400-e29b-41d4-a716-446655440000"
            if oa_format == "email":
                return "user@example.com"
            if oa_format in ("date-time", "date"):
                return "2024-01-01"

    return "1"


def resolve_path_template(
    path_template: str,
    path_parameters: list[dict[str, Any]],
    harvested_values: Optional[dict[str, str]] = None,
    synthetic_defaults: Optional[dict[str, str]] = None,
) -> str:
    """Resolve {param} placeholders to concrete values.

    Order of preference:
      1. Spec example values (from path parameter definitions)
      2. Spec default values
      3. Harvested values from prior responses
      4. Smart synthetic defaults based on name/type

    Args:
        path_template: Raw path template (e.g. "/users/{id}/posts/{postId}")
        path_parameters: List of path parameter definitions from spec
        harvested_values: Optional dict of harvested values
        synthetic_defaults: Optional dict of user-provided defaults

    Returns:
        Resolved concrete path string
    """
    resolved = path_template
    harvested = harvested_values or {}
    synthetics = synthetic_defaults or {}

    for param_def in path_parameters:
        name = param_def.get("name", "")
        placeholder = "{" + name + "}"
        if placeholder not in resolved:
            continue

        # 1. Spec example
        value = param_def.get("example")
        if value is not None:
            resolved = resolved.replace(placeholder, str(value))
            continue

        # 2. Spec default
        schema = param_def.get("schema", {})
        value = schema.get("default") if schema else None
        if value is not None:
            resolved = resolved.replace(placeholder, str(value))
            continue

        # 3. Harvested values
        if name in harvested:
            resolved = resolved.replace(placeholder, harvested[name])
            continue

        # 4. User-provided synthetic defaults
        if name in synthetics:
            resolved = resolved.replace(placeholder, synthetics[name])
            continue

        # 5. Smart synthetic
        resolved = resolved.replace(placeholder, _smart_synthetic(name, param_def))

    return resolved


# ---------------------------------------------------------------------------
# Security scheme resolution
# ---------------------------------------------------------------------------

_SECURITY_SCHEME_MAP = {
    # type: http, scheme: bearer
    "bearer": "Bearer <token>",
    # type: http, scheme: basic
    "basic": "Basic <credentials>",
}


def extract_security_headers(
    spec: dict[str, Any],
    operation_security: Optional[list[dict[str, Any]]] = None,
) -> tuple[dict[str, str], list[str]]:
    """Resolve security schemes to concrete auth header values.

    Walks spec.components.securitySchemes and resolves based on type.
    Operation-level security requirements override spec-level.

    Args:
        spec: Parsed OpenAPI spec dict
        operation_security: Optional list of security requirement refs

    Returns:
        (headers_dict, scheme_names) e.g.
            ({"Authorization": "Bearer <token>"}, ["bearer"])
    """
    headers: dict[str, str] = {}
    schemes: list[str] = []

    components = spec.get("components", {})
    security_schemes = components.get("securitySchemes", {})

    # Determine which security requirements to apply
    if operation_security is None:
        # Use spec-level security
        operation_security = spec.get("security", [])

    if not operation_security:
        return headers, schemes

    for security_req in operation_security:
        for scheme_name, scopes in security_req.items():
            scheme = security_schemes.get(scheme_name, {})
            scheme_type = scheme.get("type", "").lower()
            scheme_scheme = scheme.get("scheme", "").lower()
            scheme_in = scheme.get("in", "").lower()
            scheme_name_field = scheme.get("name", "")

            if scheme_type == "http":
                if scheme_scheme == "bearer":
                    headers["Authorization"] = "Bearer <token>"
                    schemes.append("bearer")
                elif scheme_scheme == "basic":
                    headers["Authorization"] = "Basic <credentials>"
                    schemes.append("basic")

            elif scheme_type == "apikey":
                if scheme_in == "header":
                    headers[scheme_name_field] = "<key>"
                    schemes.append(f"apikey-{scheme_name_field}")
                elif scheme_in == "query":
                    # Store as query param info (handled separately)
                    schemes.append(f"apikey-query-{scheme_name_field}")
                    # Return query param definition for downstream use
                    # This is returned via a special "query_params" key in a future enhancement

            elif scheme_type == "openIdConnect":
                # Cannot auto-resolve — log warning
                pass

    return headers, schemes


# ---------------------------------------------------------------------------
# Risk tagging
# ---------------------------------------------------------------------------

_AUTH_ENDPOINT_PATTERNS = re.compile(
    r"(login|signin|signup|register|auth|password|token|oauth|session)", re.I
)

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def compute_risk_tags(
    method: str,
    path: str,
    has_security: bool,
) -> list[str]:
    """Compute risk classification tags for an endpoint.

    Tags used by downstream stages to prioritize and gate:
      - "auth"           : endpoint uses security schemes
      - "auth-endpoint"  : path contains auth-related keywords
      - "write"          : POST/PUT/PATCH
      - "delete"         : DELETE method
      - "stateless"      : no auth required (for prioritization)
    """
    tags: list[str] = []
    method_upper = method.upper()

    if has_security:
        tags.append("auth")
    if _AUTH_ENDPOINT_PATTERNS.search(path):
        tags.append("auth-endpoint")
    if method_upper in _WRITE_METHODS:
        tags.append("write")
    if method_upper == "DELETE":
        tags.append("delete")

    return tags


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------

# Map OpenAPI "in" values to our PARAM_LOCATIONS
_IN_TO_LOCATION = {
    "query": "query",
    "header": "header",
    "cookie": "cookie",
    "path": "path",
    "body": "body_json",  # OpenAPI 3.x uses "body" for JSON body
}


def _extract_parameters(
    parameters: list[dict[str, Any]],
) -> list[ParameterModel]:
    """Extract ParameterModel objects from OpenAPI parameter definitions.

    Args:
        parameters: List of OpenAPI parameter dicts from spec

    Returns:
        List of ParameterModel objects
    """
    result: list[ParameterModel] = []

    for param_def in parameters:
        name = param_def.get("name", "")
        location = _IN_TO_LOCATION.get(param_def.get("in", ""), "query")
        schema = param_def.get("schema", {})
        oa_type = schema.get("type", "string")
        oa_format = schema.get("format")

        inferred_type = map_openapi_type(oa_type, oa_format)

        # Use example/default as raw_value if available
        raw_value = str(param_def.get("example", ""))
        if not raw_value:
            raw_value = str(schema.get("default", ""))

        result.append(ParameterModel(
            name=name,
            location=location,
            inferred_type=inferred_type,
            raw_value=raw_value,
            is_fuzz_target=True,  # All extracted params are potential targets
            do_not_fuzz=False,  # Don't skip — let targeting stage decide
        ))

    return result


def _extract_request_body(
    operation: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Extract request body schema from an operation.

    Args:
        operation: OpenAPI operation dict

    Returns:
        Request body schema dict, or None
    """
    request_body = operation.get("requestBody")
    if not request_body:
        return None

    content = request_body.get("content", {})
    # Prefer application/json
    json_content = content.get("application/json")
    if json_content:
        return json_content.get("schema")

    # Fallback: return first available schema
    for content_type, content_def in content.items():
        schema = content_def.get("schema")
        if schema:
            return schema

    return None


# ---------------------------------------------------------------------------
# Main parsing function
# ---------------------------------------------------------------------------


def _validate_openapi(spec: dict[str, Any]) -> str:
    """Validate that the spec is a recognized OpenAPI 3.x version.

    Args:
        spec: Parsed spec dict

    Returns:
        Version string (e.g. "3.0.0")

    Raises:
        OpenAPIParseError: If invalid version or structure
    """
    if not isinstance(spec, dict):
        raise OpenAPIParseError("Spec must be a JSON/YAML object")

    # Check for OpenAPI or Swagger version
    version = spec.get("openapi", spec.get("swagger", ""))
    version_str = str(version)

    if not version_str.startswith("3."):
        if version_str.startswith("2."):
            raise OpenAPIParseError(
                f"Swagger 2.0 detected. This module only supports OpenAPI 3.x. "
                f"Version found: {version_str}"
            )
        raise OpenAPIParseError(
            f"Unsupported spec version: {version_str}. "
            f"Only OpenAPI 3.x is supported."
        )

    if "paths" not in spec:
        raise OpenAPIParseError("Spec missing 'paths' key")

    return version_str


def _merge_parameters(
    path_params: list[dict[str, Any]],
    op_params: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge path-level and operation-level parameters.

    Operation-level params override path-level ones when same name+location.

    Args:
        path_params: Path-item level parameters
        op_params: Operation-level parameters

    Returns:
        Merged parameter list (operation-level takes precedence)
    """
    merged: dict[tuple[str, str], dict[str, Any]] = {}

    # Add path-level params first
    for p in path_params:
        key = (p.get("name", ""), p.get("in", "query"))
        merged[key] = p

    # Override with operation-level params
    for p in op_params:
        key = (p.get("name", ""), p.get("in", "query"))
        merged[key] = p

    return list(merged.values())


async def parse_openapi_spec(
    spec_source: str,
    scope_checker: Optional[Any] = None,
    harvested_values: Optional[dict[str, str]] = None,
    synthetic_defaults: Optional[dict[str, str]] = None,
    verify_ssl: bool = True,
    timeout: float = 30.0,
) -> OpenAPIParseResult:
    """Parse an OpenAPI 3.x spec from a URL or file path.

    Args:
        spec_source: File path or HTTP(S) URL pointing to the OpenAPI spec.
        scope_checker: Optional ScopeChecker for path filtering.
        harvested_values: Optional dict mapping path param names to concrete values.
        synthetic_defaults: Optional dict of fallback defaults for path params.
        verify_ssl: Whether to verify SSL certificates when fetching from URL.
        timeout: Timeout for fetching the spec from URL (seconds).

    Returns:
        OpenAPIParseResult with discovered endpoints.

    Raises:
        OpenAPIFetchError: If the spec cannot be fetched or read.
        OpenAPIParseError: If the spec is malformed or not a recognized OpenAPI version.
    """
    result = OpenAPIParseResult()

    # Step 1: Fetch spec content
    raw_content = await fetch_spec_content(
        spec_source=spec_source,
        verify_ssl=verify_ssl,
        timeout=timeout,
    )

    # Step 2: Parse spec body
    spec = parse_spec_body(raw_content=raw_content)
    result.spec_version = _validate_openapi(spec)
    result.spec_title = spec.get("info", {}).get("title", "Unknown")

    # Step 3: Extract base URL from servers
    servers = spec.get("servers", [])
    if servers:
        result.base_url = servers[0].get("url", "")

    # Step 4: Extract endpoints
    endpoints = _extract_endpoints(
        spec=spec,
        scope_checker=scope_checker,
        harvested_values=harvested_values,
        synthetic_defaults=synthetic_defaults,
        base_url=result.base_url,
    )
    result.endpoints = endpoints
    result.total_endpoints = len(endpoints)

    return result


async def fetch_spec_content(
    spec_source: str,
    verify_ssl: bool = True,
    timeout: float = 30.0,
) -> str:
    """Fetch spec content from file or URL.

    Args:
        spec_source: File path or HTTP(S) URL
        verify_ssl: Whether to verify SSL certificates
        timeout: Timeout for HTTP requests

    Returns:
        Raw YAML/JSON string content

    Raises:
        OpenAPIFetchError: On I/O failure
    """
    if spec_source.startswith(("http://", "https://")):
        try:
            async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
                resp = await client.get(spec_source)
                resp.raise_for_status()
                return resp.text
        except httpx.HTTPError as e:
            raise OpenAPIFetchError(f"Failed to fetch spec from URL: {e}") from e
        except Exception as e:
            raise OpenAPIFetchError(f"Failed to fetch spec: {e}") from e
    else:
        # File path
        try:
            return Path(spec_source).read_text(encoding="utf-8")
        except OSError as e:
            raise OpenAPIFetchError(f"Cannot read spec file: {e}") from e


def parse_spec_body(raw_content: str) -> dict[str, Any]:
    """Parse raw YAML/JSON string into a Python dict.

    Detects format by trying JSON first, then YAML.

    Args:
        raw_content: Raw spec content string

    Returns:
        Parsed spec dict

    Raises:
        OpenAPIParseError: If content is not valid YAML/JSON or not OpenAPI 3.x
    """
    # Try JSON first
    try:
        spec = json.loads(raw_content)
        return spec
    except json.JSONDecodeError:
        pass

    # Try YAML (lazy import — optional dependency)
    try:
        import yaml
        spec = yaml.safe_load(raw_content)
        if isinstance(spec, dict):
            return spec
        raise OpenAPIParseError("YAML spec must be a mapping (object)")
    except ImportError:
        raise OpenAPIParseError(
            "YAML parsing requires pyyaml. Install with: pip install pyyaml"
        )
    except Exception as e:
        raise OpenAPIParseError(f"Spec is not valid JSON or YAML: {e}") from e


def _extract_endpoints(
    spec: dict[str, Any],
    scope_checker: Optional[Any] = None,
    harvested_values: Optional[dict[str, str]] = None,
    synthetic_defaults: Optional[dict[str, str]] = None,
    base_url: Optional[str] = None,
) -> list[DiscoveredEndpoint]:
    """Extract DiscoveredEndpoint objects from a parsed OpenAPI spec dict.

    Walks paths/methods/parameters/requestBodies/security schemes and
    produces the endpoint list.

    Args:
        spec: Parsed OpenAPI spec dict
        scope_checker: Optional ScopeChecker for path filtering
        harvested_values: Optional dict of harvested path param values
        synthetic_defaults: Optional dict of synthetic path param defaults
        base_url: Base URL from spec servers

    Returns:
        List of DiscoveredEndpoint objects
    """
    endpoints: list[DiscoveredEndpoint] = []
    paths = spec.get("paths", {})

    # Resolve global security schemes for later reference
    components = spec.get("components", {})
    security_schemes = components.get("securitySchemes", {})

    # Get spec-level security requirements
    spec_security = spec.get("security", [])

    for path_template, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Extract path-level parameters
        path_params = path_item.get("parameters", [])

        # Iterate over HTTP methods
        for method in ("get", "post", "put", "delete", "patch", "head", "options", "trace"):
            operation = path_item.get(method)
            if not operation or not isinstance(operation, dict):
                continue

            # Merge path-level and operation-level parameters
            op_params = operation.get("parameters", [])
            merged_params = _merge_parameters(path_params, op_params)

            # Extract parameters
            parameters = _extract_parameters(merged_params)

            # Extract request body
            body_schema = _extract_request_body(operation)

            # Resolve security
            operation_security = operation.get("security", spec_security)
            auth_headers, scheme_names = extract_security_headers(
                spec=spec,
                operation_security=operation_security,
            )

            # Resolve path template
            path_level_params = path_item.get("parameters", [])
            concrete_path = resolve_path_template(
                path_template=path_template,
                path_parameters=path_level_params,
                harvested_values=harvested_values,
                synthetic_defaults=synthetic_defaults,
            )

            # Compute risk tags
            has_security = bool(operation_security)
            risk_tags = compute_risk_tags(
                method=method,
                path=path_template,
                has_security=has_security,
            )

            # Scope filtering
            if scope_checker is not None:
                test_url = f"{base_url or ''}{concrete_path}"
                try:
                    scope_checker.check(
                        url=test_url,
                        method=method.upper(),
                        description=f"OpenAPI: {method.upper()} {path_template}",
                    )
                except Exception:
                    # Out of scope — skip
                    continue

            endpoint = DiscoveredEndpoint(
                method=method.upper(),
                path_template=path_template,
                concrete_path=concrete_path,
                parameters=parameters,
                body_schema=body_schema,
                source="openapi",
                risk_tags=risk_tags,
                base_url=base_url,
            )
            endpoints.append(endpoint)

    return endpoints
