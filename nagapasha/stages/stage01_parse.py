"""Stage 1 — cURL Ingestion & Parameter Parser.

Parses a curl command string into a structured RequestModel.
Handles common flags and infers parameter types via regex heuristics.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, urlunparse

from nagapasha.models.request_model import ParameterModel, RequestModel


# ---------------------------------------------------------------------------
# Type inference
# ---------------------------------------------------------------------------

_TYPE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # JWT: three base64url segments separated by dots (header.payload.signature)
    # Each segment must be at least 5 chars of base64url characters
    ("jwt", re.compile(r"^[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}$")),
    ("uuid", re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")),
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")),
    ("filename", re.compile(r"\.(jpg|jpeg|png|gif|pdf|txt|doc|docx|zip|tar|gz|csv|json|xml|html?)$", re.I)),
    ("date", re.compile(r"^\d{4}-\d{2}-\d{2}")),
    ("int", re.compile(r"^-?\d+$")),
    ("boolean", re.compile(r"^(true|false|yes|no)$", re.I)),
]


def infer_type(value: str) -> str:
    """Infer a parameter type from its value using regex heuristics."""
    for type_name, pattern in _TYPE_PATTERNS:
        if pattern.search(value):
            return type_name
    return "free_text"


# ---------------------------------------------------------------------------
# Auth header detection
# ---------------------------------------------------------------------------

_AUTH_PATTERNS = re.compile(
    r"^(authorization|x-auth-token|x-api-key|cookie|set-cookie)$", re.I
)


def is_auth_param(name: str) -> bool:
    """Return True if the parameter name looks like an auth token."""
    return bool(_AUTH_PATTERNS.match(name))


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------


def parse_url(url_str: str) -> tuple[str, list[str], dict[str, str]]:
    """Split a URL into base_url, path_segments, and query_params.

    Returns:
        (base_url, path_segments, query_params)
    """
    parsed = urlparse(url_str)
    base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    # Path segments
    path = parsed.path.strip("/")
    path_segments = [s for s in path.split("/") if s]

    # Query parameters
    query_params = dict(parse_qs(parsed.query, keep_blank_values=True))
    # Flatten single-value dicts
    query_params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}

    return base, path_segments, query_params


# ---------------------------------------------------------------------------
# Cookie parsing
# ---------------------------------------------------------------------------


def parse_cookies(cookies_str: str) -> dict[str, str]:
    """Parse a cookie header string like 'key1=val1; key2=val2'."""
    cookies: dict[str, str] = {}
    if not cookies_str:
        return cookies
    for part in cookies_str.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, val = part.partition("=")
            cookies[key.strip()] = val.strip()
    return cookies


# ---------------------------------------------------------------------------
# Body parsing
# ---------------------------------------------------------------------------


def detect_body_type(body: str) -> str:
    """Detect the body type from content."""
    stripped = body.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            json.loads(stripped)
            return "json"
        except json.JSONDecodeError:
            pass
    if "=" in stripped and "&" in stripped:
        return "form"
    if "Content-Type: multipart" in stripped or boundary_in_body(stripped):
        return "multipart"
    return "raw"


def boundary_in_body(body: str) -> bool:
    """Check if body contains a multipart boundary marker."""
    return "--boundary" in body or re.search(r"--\w+", body) is not None


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


class CurlParseError(Exception):
    """Raised when a curl command cannot be parsed."""


def parse_curl(curl_command: str) -> RequestModel:
    """Parse a curl command string into a RequestModel.

    Handles:
        -X METHOD
        URL (first positional)
        -H 'Header: Value' (multiple)
        -d 'data' / -d @file / --data-binary @file / --data-urlencode key=val
        -b 'key=val' (cookies)
        -u 'user:pass' (basic auth)
        -k (insecure, ignored for parsing)

    If method is not explicitly specified via -X, prompts the user to confirm.

    Args:
        curl_command: The full curl command as a string.

    Returns:
        A RequestModel with all parsed fields.

    Raises:
        CurlParseError: If the command is malformed.
    """
    # Tokenize using shlex for safe parsing
    try:
        tokens = shlex.split(curl_command)
    except ValueError as e:
        raise CurlParseError(f"Failed to tokenize curl command: {e}") from e

    if not tokens or tokens[0] != "curl":
        raise CurlParseError("Command must start with 'curl'")

    # Parse flags
    method = ""  # Empty until confirmed
    url = ""
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    body: Optional[str] = None
    data_urlencode: dict[str, str] = {}
    basic_auth: Optional[str] = None
    has_data_flag = False  # Track if -d, --data-binary, or --data-urlencode present

    i = 1
    while i < len(tokens):
        token = tokens[i]

        if token == "-X" and i + 1 < len(tokens):
            method = tokens[i + 1].upper()
            i += 2
        elif token == "-d" or token == "--data" or token == "--data-raw":
            has_data_flag = True
            if i + 1 < len(tokens):
                d = tokens[i + 1]
                if d.startswith("@"):
                    # Read from file
                    try:
                        with open(d[1:], "r") as f:
                            body = f.read()
                    except OSError as e:
                        raise CurlParseError(f"Failed to read data file: {e}") from e
                else:
                    body = d
                i += 2
            else:
                i += 1
        elif token == "--data-binary":
            has_data_flag = True
            if i + 1 < len(tokens):
                d = tokens[i + 1]
                if d.startswith("@"):
                    try:
                        with open(d[1:], "rb") as f:
                            body = f.read().decode("utf-8", errors="replace")
                    except OSError as e:
                        raise CurlParseError(f"Failed to read binary data file: {e}") from e
                else:
                    body = d
                i += 2
            else:
                i += 1
        elif token == "--data-urlencode":
            has_data_flag = True
            if i + 1 < len(tokens):
                de = tokens[i + 1]
                if "=" in de:
                    k, _, v = de.partition("=")
                    data_urlencode[k.strip()] = v.strip()
                i += 2
            else:
                i += 1
        elif token == "-H":
            if i + 1 < len(tokens):
                h = tokens[i + 1]
                if ":" in h:
                    key, _, val = h.partition(":")
                    headers[key.strip()] = val.strip()
                i += 2
            else:
                i += 1
        elif token == "-b":
            if i + 1 < len(tokens):
                c = tokens[i + 1]
                parsed = parse_cookies(c)
                cookies.update(parsed)
                i += 2
            else:
                i += 1
        elif token == "-u":
            if i + 1 < len(tokens):
                basic_auth = tokens[i + 1]
                i += 2
            else:
                i += 1
        elif token == "-k" or token == "--insecure":
            # Ignored for parsing
            i += 1
        elif token.startswith("-"):
            # Skip unknown flags and their values
            i += 1
        else:
            # Positional — the URL (first non-flag argument)
            if not url:
                url = token
            i += 1

    if not url:
        raise CurlParseError("No URL found in curl command")

    # Add basic auth header if specified
    if basic_auth:
        headers["Authorization"] = f"Basic {basic_auth}"

    # Add data-urlencode to body or query
    if data_urlencode:
        if body is None:
            # Add to query params
            if not url.startswith("http"):
                url = "https://" + url
            parsed = urlparse(url)
            existing_q = dict(parse_qs(parsed.query, keep_blank_values=True))
            existing_q.update(data_urlencode)
            from urllib.parse import urlencode, urlunparse
            new_query = urlencode(existing_q)
            url = urlunparse(parsed._replace(query=new_query))
        else:
            # Append to body
            from urllib.parse import urlencode
            appended = urlencode(data_urlencode)
            body = (body + "&" + appended) if body else appended

    # Detect body type
    body_type = None
    if body is not None:
        body_type = detect_body_type(body)
        # Set content-type if not present
        has_ct = any(k.lower() == "content-type" for k in headers)
        if not has_ct:
            if body_type == "json":
                headers["Content-Type"] = "application/json"
            elif body_type == "form":
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif body_type == "multipart":
                headers["Content-Type"] = "multipart/form-data"

    # Parse URL into components
    base_url, path_segments, query_params = parse_url(url)

    # Build parameters
    parameters: list[ParameterModel] = []

    # Query params
    for name, value in query_params.items():
        value_str = str(value)
        parameters.append(ParameterModel(
            name=name,
            location="query",
            inferred_type=infer_type(value_str),
            raw_value=value_str,
            is_fuzz_target=False,
            do_not_fuzz=is_auth_param(name),
        ))

    # Path segments (as parameters for fuzzing)
    for i, seg in enumerate(path_segments):
        parameters.append(ParameterModel(
            name=f"path[{i}]",
            location="path",
            inferred_type=infer_type(seg),
            raw_value=seg,
            is_fuzz_target=False,
            do_not_fuzz=False,
        ))

    # Body params
    if body is not None:
        if body_type == "json":
            try:
                body_obj = json.loads(body)
                for k, v in (body_obj.items() if isinstance(body_obj, dict)
                             else enumerate(body_obj)):
                    v_str = str(v)
                    parameters.append(ParameterModel(
                        name=str(k) if isinstance(k, int) else k,
                        location="body_json",
                        inferred_type=infer_type(v_str),
                        raw_value=v_str,
                        is_fuzz_target=False,
                        do_not_fuzz=is_auth_param(str(k) if isinstance(k, int) else k),
                    ))
            except json.JSONDecodeError:
                parameters.append(ParameterModel(
                    name="body",
                    location="body_json",
                    inferred_type="free_text",
                    raw_value=body[:200],
                    is_fuzz_target=False,
                    do_not_fuzz=False,
                ))
        elif body_type == "form":
            form_params = dict(parse_qs(body, keep_blank_values=True))
            for name, value in form_params.items():
                parameters.append(ParameterModel(
                    name=name,
                    location="body_form",
                    inferred_type=infer_type(str(value)),
                    raw_value=str(value),
                    is_fuzz_target=False,
                    do_not_fuzz=is_auth_param(name),
                ))
        else:
            # Raw body
            parameters.append(ParameterModel(
                name="body",
                location=body_type,
                inferred_type="free_text",
                raw_value=body[:200],
                is_fuzz_target=False,
                do_not_fuzz=False,
            ))

    # Headers (as parameters, excluding auth tokens)
    for name, value in headers.items():
        if name.lower() not in ("authorization", "cookie", "host"):
            parameters.append(ParameterModel(
                name=name,
                location="header",
                inferred_type=infer_type(value),
                raw_value=value,
                is_fuzz_target=False,
                do_not_fuzz=is_auth_param(name),
            ))

    # Cookies (as parameters)
    for name, value in cookies.items():
        parameters.append(ParameterModel(
            name=name,
            location="cookie",
            inferred_type=infer_type(value),
            raw_value=value,
            is_fuzz_target=False,
            do_not_fuzz=is_auth_param(name),
        ))

    # Auto-detect method if not explicitly specified
    if not method:
        import logging
        logger = logging.getLogger(__name__)

        # If data flags were present, auto-detect POST
        if has_data_flag:
            logger.info("Auto-detected POST method from -d/--data/--data-raw/--data-binary flags")
            method = "POST"
        else:
            # No data, no method specified - default to GET with warning
            logger.warning(
                "HTTP method not specified in curl command. Defaulting to GET. "
                "Use -X METHOD flag to specify the method (GET, POST, PUT, PATCH, DELETE, etc.)"
            )
            method = "GET"

    return RequestModel(
        method=method,
        url=url,
        base_url=base_url,
        headers=headers,
        cookies=cookies,
        body=body,
        body_type=body_type,
        query_params=query_params,
        path_segments=path_segments,
        parameters=parameters,
    )
