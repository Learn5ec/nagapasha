"""Session manager — login capture and session injection.

Captures session state from login responses (cookies, auth headers, localStorage)
and injects that state into subsequent requests for authenticated scanning.

Supports:
  - Cookie-based sessions (Set-Cookie headers)
  - Bearer token sessions (response body or header)
  - HTTP Basic auth (request Authorization header)
  - JWT tokens (response body)
  - Custom auth header schemes
  - Session expiration detection
  - Session refresh

Usage:
  1. establish_session(login_curl) -> SessionContext
  2. inject_session(request_model, session) -> RequestModel
  3. Check session.expires_at before batches; if expired, re-establish
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from nagapasha.models.request_model import RequestModel


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class SessionContext:
    """Captured session state from a login response.

    Attributes:
        label: Human-readable label (e.g. "user_a", "admin")
        cookies: Captured cookies (name -> value)
        auth_header: Captured Authorization header value (e.g. "Bearer <token>")
        local_storage: Captured localStorage values (key -> value)
        expires_at: Session expiration time (None if unknown)
        session_id: Unique ID for this session
    """

    label: str = "default"
    cookies: dict[str, str] = field(default_factory=dict)
    auth_header: Optional[str] = None
    local_storage: dict[str, str] = field(default_factory=dict)
    expires_at: Optional[datetime] = None
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])


@dataclass
class SessionEstablishmentResult:
    """Structured output of session establishment.

    Attributes:
        session: Captured session context
        success: Whether session was established successfully
        error: Error message if unsuccessful
        auth_method: Detected auth method (cookie, bearer, basic, jwt)
    """

    session: Optional[SessionContext] = None
    success: bool = False
    error: Optional[str] = None
    auth_method: Optional[str] = None


# ---------------------------------------------------------------------------
# Cookie extraction
# ---------------------------------------------------------------------------


def extract_cookies_from_headers(headers: dict[str, str]) -> dict[str, str]:
    """Extract cookies from Set-Cookie headers.

    Args:
        headers: Response headers dict

    Returns:
        Dict of cookie name -> value
    """
    cookies = {}

    for key, value in headers.items():
        if key.lower() == "set-cookie":
            # Parse Set-Cookie header (format: name=value; Path=/; HttpOnly; Secure)
            match = re.match(r"([^=;]+)\s*=\s*([^;]+)", value)
            if match:
                name = match.group(1).strip()
                val = match.group(2).strip()
                cookies[name] = val

    return cookies


# ---------------------------------------------------------------------------
# Token extraction
# ---------------------------------------------------------------------------


def extract_token_from_response(body: str, headers: dict[str, str]) -> Optional[str]:
    """Extract auth token from response body or headers.

    Checks for:
      - Authorization header
      - JWT token in response body (JSON)
      - Access token in response body (JSON)
      - Session ID in response body (JSON)

    Args:
        body: Response body string
        headers: Response headers dict

    Returns:
        Token string, or None
    """
    # Check Authorization header first
    auth = headers.get("Authorization", "")
    if auth and auth.startswith("Bearer "):
        return auth

    # Try parsing JSON body
    try:
        data = json.loads(body) if body else None
    except (json.JSONDecodeError, TypeError):
        data = None

    if not data or not isinstance(data, dict):
        return None

    # Look for common token field names
    token_fields = [
        "token",
        "access_token",
        "refresh_token",
        "session_id",
        "session",
        "jwt",
        "id_token",
    ]

    for field_name in token_fields:
        value = data.get(field_name)
        if value and isinstance(value, str):
            return value

    # Check for nested token (e.g., data.token, credentials.token)
    nested_fields = ["data", "credentials", "user", "result"]
    for prefix in nested_fields:
        nested = data.get(prefix)
        if nested and isinstance(nested, dict):
            for field_name in token_fields:
                value = nested.get(field_name)
                if value and isinstance(value, str):
                    return value

    return None


# ---------------------------------------------------------------------------
# LocalStorage extraction
# ---------------------------------------------------------------------------


def extract_local_storage_from_body(body: str) -> dict[str, str]:
    """Extract localStorage values from SPA response body.

    Looks for common patterns:
      - window.localStorage.setItem(...)
      - localStorage.setItem(...)
      - LocalStorage.setItem(...)

    Args:
        body: Response body string

    Returns:
        Dict of key -> value
    """
    local_storage: dict[str, str] = {}

    if not body:
        return local_storage

    # Pattern: key: "value" or key: "value", (JSON-like)
    json_pattern = re.compile(r'"([^"]+)":\s*"([^"]+)"')
    for match in json_pattern.finditer(body):
        key = match.group(1)
        value = match.group(2)
        if key.lower() in ("token", "access_token", "session_id", "jwt"):
            local_storage[key] = value

    # Pattern: setItem('key', 'value') or setItem("key", "value")
    setitem_pattern = re.compile(
        r'(?:window\.)?localStorage\.(?:setItem|setItemIf)\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']*)["\']'
    )
    for match in setitem_pattern.finditer(body):
        key = match.group(1)
        value = match.group(2)
        if key.lower() in ("token", "access_token", "session_id", "jwt"):
            local_storage[key] = value

    return local_storage


# ---------------------------------------------------------------------------
# Expiration detection
# ---------------------------------------------------------------------------


def detect_expiration(headers: dict[str, str], body: str) -> Optional[datetime]:
    """Detect session expiration from response headers or body.

    Looks for:
      - Set-Cookie with Max-Age or Expires attribute
      - response_body.expires_at
      - response_body.expires_in (seconds from now)

    Args:
        headers: Response headers
        body: Response body

    Returns:
        Expiration datetime, or None
    """
    # Check Set-Cookie for Max-Age or Expires
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            # Parse Max-Age
            max_age_match = re.search(r"Max-Age\s*=\s*(\d+)", value, re.I)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                return datetime.now(timezone.utc) + timedelta(seconds=max_age)

            # Parse Expires
            expires_match = re.search(r"Expires\s*=\s*([^;]+)", value, re.I)
            if expires_match:
                try:
                    from email.utils import parsedate_to_datetime
                    expires_str = expires_match.group(1).strip()
                    expires_dt = parsedate_to_datetime(expires_str)
                    if expires_dt:
                        return expires_dt.replace(tzinfo=timezone.utc)
                except Exception:
                    pass

    # Check body for expires_at or expires_in
    try:
        data = json.loads(body) if body else None
        if data and isinstance(data, dict):
            # Check expires_at (ISO string)
            expires_at = data.get("expires_at")
            if expires_at:
                try:
                    from dateutil.parser import parse
                    return parse(expires_at).replace(tzinfo=timezone.utc)
                except ImportError:
                    pass

            # Check expires_in (seconds from now)
            expires_in = data.get("expires_in")
            if expires_in and isinstance(expires_in, (int, float)):
                return datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    except (json.JSONDecodeError, TypeError):
        pass

    return None


# ---------------------------------------------------------------------------
# Session establishment
# ---------------------------------------------------------------------------


async def establish_session(
    login_curl: str,
    runner: Any,  # HttpRunner
    scope_checker: Optional[Any] = None,
    label: str = "default",
) -> SessionEstablishmentResult:
    """Establish a session from a login curl command.

    Parses a curl-like command, extracts HTTP method/URL/headers/body,
    fires the login request via the runner, and captures session state:
      - Set-Cookie headers
      - Authorization / Bearer / API-key headers
      - JWT tokens in response body
      - localStorage tokens (SPA-style)
      - Expiration from Set-Cookie or response body

    Args:
        login_curl: Curl command for login (e.g. "curl -X POST https://...")
        runner: HttpRunner for executing the login request
        scope_checker: Optional ScopeChecker for authorization gating
        label: Human-readable label for this session

    Returns:
        SessionEstablishmentResult with captured session state
    """
    result = SessionEstablishmentResult()
    result.session = SessionContext(label=label)

    try:
        # Parse the curl command into RequestModel fields
        method, url, headers, body, body_type = _parse_curl(login_curl)

        # Build the request model
        request = RequestModel(
            method=method,
            url=url,
            base_url=url,
            headers=headers or {},
            body=body,
            body_type=body_type,
        )

        # Send the login request
        response = await runner.send(request)

        # Extract session state from the response
        session = _capture_session(
            status_code=response.status_code,
            headers=response.headers,
            body=response.body,
            label=label,
        )

        result.session = session
        result.success = bool(session.cookies or session.auth_header or session.local_storage)
        result.auth_method = _detect_auth_method(session)

    except Exception as e:
        result.error = str(e)
        result.success = False

    return result


def _parse_curl(curl_cmd: str) -> tuple[str, str, Optional[dict[str, str]], Optional[str], Optional[str]]:
    """Parse a curl command into HTTP method, URL, headers, body, body_type.

    Supports:
      - curl -X POST https://... -H "Key: Value" -d '{"json":"data"}'
      - curl -X GET https://... -H "Authorization: Bearer ..."
      - curl https://... (GET by default)
      - curl -X POST https://... -F "key=value" (form data)

    Args:
        curl_cmd: The curl command string

    Returns:
        Tuple of (method, url, headers, body, body_type)
    """
    method = "GET"
    url = ""
    headers: dict[str, str] = {}
    body = None
    body_type = None

    # Extract -X method
    import re
    method_match = re.search(r"-X\s+(\w+)", curl_cmd, re.I)
    if method_match:
        method = method_match.group(1).upper()

    # Extract URL — regex finds the first URL-like token
    url_match = re.search(r"(https?://\S+)", curl_cmd)
    if url_match:
        url = url_match.group(1)
    else:
        # Fallback: first positional arg that isn't a flag
        tokens = curl_cmd.split()
        for token in tokens:
            if not token.startswith("-") and token != "curl":
                url = token
                break

    # Extract headers
    header_matches = re.findall(r'-[hH]\s+["\']([^"\']*)["\']', curl_cmd)
    for header_str in header_matches:
        if ":" in header_str:
            key, value = header_str.split(":", 1)
            headers[key.strip()] = value.strip()

    # Extract body (-d or -F) — wrapper quote is captured and matched via backreference
    data_match = re.search(r"-[dF]\s+(['\"])(.*?)\1", curl_cmd, re.S)
    if not data_match:
        data_match = re.search(r"-[dF]\s+(\S+)", curl_cmd, re.S)
    if data_match:
        body = data_match.group(2) if len(data_match.groups()) > 1 else data_match.group(1)
        # Detect body type from Content-Type header or content
        if headers.get("Content-Type", "").lower() == "application/json":
            body_type = "application/json"
        elif headers.get("Content-Type", "").lower().startswith("multipart"):
            body_type = "multipart/form-data"
        elif headers.get("Content-Type", ""):
            body_type = headers["Content-Type"]
        else:
            # Infer from content
            try:
                json.loads(body)
                body_type = "application/json"
            except (json.JSONDecodeError, TypeError):
                if "=" in body and "&" in body:
                    body_type = "application/x-www-form-urlencoded"
                else:
                    body_type = "text/plain"

    return method, url, headers, body, body_type


def _capture_session(
    status_code: int,
    headers: dict[str, str],
    body: str,
    label: str,
) -> SessionContext:
    """Capture session state from a login response.

    Args:
        status_code: HTTP status code
        headers: Response headers
        body: Response body
        label: Session label

    Returns:
        SessionContext with captured state
    """
    session = SessionContext(label=label)

    # Extract cookies
    session.cookies = extract_cookies_from_headers(headers)

    # Extract auth token from response
    token = extract_token_from_response(body, headers)
    if token:
        # Check if it's a Bearer token
        if token.startswith("Bearer "):
            session.auth_header = token
        else:
            session.auth_header = f"Bearer {token}"

    # Extract localStorage tokens (SPA-style)
    session.local_storage = extract_local_storage_from_body(body)

    # Detect expiration
    session.expires_at = detect_expiration(headers, body)

    return session


def _detect_auth_method(session: SessionContext) -> Optional[str]:
    """Detect the auth method used by this session.

    Args:
        session: Captured session

    Returns:
        Auth method string (cookie, bearer, basic, jwt, or None)
    """
    if session.cookies:
        return "cookie"
    if session.auth_header:
        if session.auth_header.startswith("Bearer "):
            return "bearer"
        if session.auth_header.startswith("Basic "):
            return "basic"
        return "custom"
    if session.local_storage:
        return "jwt"
    return None


# ---------------------------------------------------------------------------
# Session injection
# ---------------------------------------------------------------------------


def inject_session(
    request_model: RequestModel,
    session: SessionContext,
) -> RequestModel:
    """Inject session state into a request model.

    Modifies the request to include:
      - Authorization header (if auth_header is set)
      - Cookie header (if cookies are set)
      - Custom headers (if local_storage has tokens)

    Args:
        request_model: Original request model
        session: Session context to inject

    Returns:
        Modified request model with session injected
    """
    # Make a copy to avoid mutating the original
    import copy
    modified = copy.deepcopy(request_model)

    # Inject Authorization header
    if session.auth_header:
        if modified.headers is None:
            modified.headers = {}
        modified.headers["Authorization"] = session.auth_header

    # Inject Cookie header
    if session.cookies:
        if modified.headers is None:
            modified.headers = {}
        cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
        modified.headers["Cookie"] = cookie_str

    # Inject localStorage tokens as headers (if any)
    if session.local_storage:
        if modified.headers is None:
            modified.headers = {}
        for key, value in session.local_storage.items():
            # Convert to header format: X-LocalStorage-Key
            header_name = f"X-LocalStorage-{key.capitalize()}"
            modified.headers[header_name] = value

    return modified


# ---------------------------------------------------------------------------
# Session validation
# ---------------------------------------------------------------------------


def is_session_valid(session: SessionContext) -> bool:
    """Check if a session is still valid (not expired).

    Args:
        session: Session to check

    Returns:
        True if session is valid, False otherwise
    """
    if not session:
        return False

    if session.expires_at is None:
        # No expiration set — assume valid
        return True

    now = datetime.now(timezone.utc)
    if now >= session.expires_at:
        return False

    return True
