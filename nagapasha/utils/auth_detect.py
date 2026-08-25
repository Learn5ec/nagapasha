"""Auth-endpoint detection for Stage 3+ targeting.

Identifies whether a RequestModel targets an authentication endpoint by
checking:
  (a) URL path patterns: login, signin, register, signup, auth, etc.
  (b) Body content: JSON body contains both credential-like AND
      email/username-like field names (the "email + password" co-occurrence
      pattern that any conventional login form has).

This flag is used only to set *priority* for technique-category selection —
it does not inject hardcoded bypass strings.
"""

from __future__ import annotations

from nagapasha.models.request_model import RequestModel

AUTH_PATH_KEYWORDS: tuple[str, ...] = (
    "login", "signin", "sign-in", "sign_in", "auth", "authenticate",
    "register", "signup", "sign-up", "sign_up", "create-account",
    "password-reset", "forgot-password", "token", "oauth", "callback",
)

CREDENTIAL_LIKE_FIELDS: tuple[str, ...] = (
    "email", "e-mail", "username", "user", "login",
)

PASSWORD_LIKE_FIELDS: tuple[str, ...] = (
    "password", "pass", "pwd",
)


def detect_auth_endpoint(request_model: RequestModel) -> bool:
    """Return True if the request targets an authentication endpoint.

    Detection uses URL path patterns AND/OR body content co-occurrence.
    Either signal is sufficient.
    """
    if _detect_by_url(request_model):
        return True
    return _detect_by_body(request_model)


def _detect_by_url(req: RequestModel) -> bool:
    """Check URL path for auth-related keywords."""
    url_lower = req.url.lower()
    return any(kw in url_lower for kw in AUTH_PATH_KEYWORDS)


def _detect_by_body(req: RequestModel) -> bool:
    """Check JSON body for email/username AND password field co-occurrence."""
    if not req.body:
        return False
    # Quick check: does the raw body string contain both field types?
    body_lower = req.body.lower()
    has_credential = any(f in body_lower for f in CREDENTIAL_LIKE_FIELDS)
    has_password = any(f in body_lower for f in PASSWORD_LIKE_FIELDS)
    return has_credential and has_password
