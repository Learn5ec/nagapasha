"""Intent parser — user-directed surplus scan.

Resolves natural-language user requests into technique-category keys, target
locations, and dialect hints. The LLM output is validated against a JSON
Schema derived dynamically from TECHNIQUE_CATEGORIES.keys() at call time —
never hardcoded.

Hard rule: resolve_intent() selects from the fixed, known TECHNIQUE_CATEGORIES
dict — it returns category keys (strings that must assert in TECHNIQUE_CATEGORIES),
never freeform payload strings. If validation fails (model hallucinates a category
name), fall back to unsupported_asks for that portion of the request rather than
passing an invalid/freeform payload downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from nagapasha.models.request_model import RequestModel, TechStackContext


@dataclass
class IntentResolution:
    """Resolution of a user's natural-language intent into technique-category keys."""

    resolved_categories: list[str] = field(default_factory=list)
    target_locations: Optional[list[str]] = None
    dialect_hint: Optional[str] = None
    unsupported_asks: list[str] = field(default_factory=list)
    out_of_reach_asks: list[str] = field(default_factory=list)
    rationale: str = ""


# Known technique categories that the intent parser can route to
# (imported at call time from TECHNIQUE_CATEGORIES.keys())

# Structural impossibilities without Phase E/browser
STRUCTURALLY_IMPOSSIBLE = frozenset({
    "confirmed_xss_execution",
    "stored_xss_verification",
    "browser_xss_proof",
    "client_side_hardening",
    "csp_check",
})


def _intent_response_schema() -> dict:
    """JSON Schema for the LLM's structured output — enum is derived live from
    TECHNIQUE_CATEGORIES so it can never drift out of sync with what the tool
    actually supports.
    """
    from nagapasha.utils.technique_categories import TECHNIQUE_CATEGORIES
    return _build_schema_from(TECHNIQUE_CATEGORIES)


def _build_schema_from(categories: dict) -> dict:
    """Internal helper: build schema dict from a TECHNIQUE_CATEGORIES-like dict."""
    valid_categories = sorted(categories.keys())
    return {
        "type": "object",
        "properties": {
            "resolved_categories": {
                "type": "array",
                "items": {"type": "string", "enum": valid_categories},
            },
            "target_locations": {
                "type": ["array", "null"],
                "items": {"type": "string"},
            },
            "dialect_hint": {"type": ["string", "null"]},
            "unsupported_asks": {"type": "array", "items": {"type": "string"}},
            "out_of_reach_asks": {"type": "array", "items": {"type": "string"}},
            "rationale": {"type": "string"},
        },
        "required": ["resolved_categories", "unsupported_asks",
                     "out_of_reach_asks", "rationale"],
        "additionalProperties": False,
    }


# ---------------------------------------------------------------------------
# Keyword-to-category mapping (deterministic, no LLM required for simple cases)
# ---------------------------------------------------------------------------

# Map keywords to a single category string (most specific match)
KEYWORD_TO_CATEGORY = {
    # XSS
    "xss": "xss_reflected",
    "cross-site scripting": "xss_reflected",
    "reflected script": "xss_reflected",
    # HTML injection
    "html injection": "html_injection",
    "output encoding": "html_injection",
    "markup": "html_injection",
    # Path traversal
    "path traversal": "path_traversal",
    "lfi": "path_traversal",
    "local file inclusion": "path_traversal",
    "file read": "path_traversal",
    "file disclosure": "path_traversal",
    # Time-based blind
    "time-based": "time_based_blind",
    "blind sql": "time_based_blind",
    "delay": "time_based_blind",
    # Boolean blind
    "boolean blind": "boolean_differential",
    "boolean-based": "boolean_differential",
    # Union-based
    "union": "union_based",
    "data extraction": "union_based",
    # Stacked query
    "stacked": "stacked_query",
    "stacked query": "stacked_query",
}

# Map keywords to AUTH_PRIORITY_CATEGORIES (multi-category resolution)
# These keywords resolve to BOTH tautology AND boolean_differential for
# comprehensive auth-endpoint testing (P3-2 fix).
KEYWORD_TO_AUTH_CATEGORIES: dict[str, tuple[str, ...]] = {
    "login bypass": ("tautology", "boolean_differential"),
    "auth bypass": ("tautology", "boolean_differential"),
    "password bypass": ("tautology", "boolean_differential"),
    "credential": ("tautology", "boolean_differential"),
    # SQL injection — use both tautology and boolean for comprehensive coverage
    "sql injection": ("tautology", "boolean_differential"),
    "sqli": ("tautology", "boolean_differential"),
}

# Categories that structurally require Phase E/browser
OUT_OF_REACH_KEYWORDS = frozenset({
    "confirmed execution",
    "stored xss",
    "browser proof",
    "csp",
    "content security policy",
})


async def resolve_intent(
    user_text: str,
    tech_stack: Optional[TechStackContext] = None,
    request_model: Optional[RequestModel] = None,
    runner=None,  # AnthropicRunner (optional — not needed for deterministic resolution)
) -> IntentResolution:
    """Resolve a user's natural-language intent into technique-category keys.

    Uses deterministic keyword mapping first. If runner is provided, falls back
    to LLM enrichment with schema derived from TECHNIQUE_CATEGORIES.keys().

    Args:
        user_text: User's natural-language request (e.g. "test for XSS in JSON params")
        tech_stack: Optional TechStackContext with database field for dialect_hint
        request_model: Optional RequestModel for CRUD/method awareness
        runner: Optional AnthropicRunner for LLM enrichment

    Returns:
        IntentResolution with resolved_categories, target_locations, dialect_hint,
        unsupported_asks, out_of_reach_asks, rationale
    """
    resolution = IntentResolution()
    user_text_lower = user_text.lower()

    # Step 1: Deterministic keyword mapping
    # Multi-category keywords (auth bypass, SQLi) resolve to AUTH_PRIORITY_CATEGORIES
    # Single-category keywords (XSS, HTML injection, etc.) map to a single category.
    for keyword, target in KEYWORD_TO_AUTH_CATEGORIES.items():
        if keyword in user_text_lower:
            for cat in target:
                if cat not in resolution.resolved_categories:
                    resolution.resolved_categories.append(cat)

    for keyword, category in KEYWORD_TO_CATEGORY.items():
        if keyword in user_text_lower:
            if category not in resolution.resolved_categories:
                resolution.resolved_categories.append(category)

    # Step 2: Check for out-of-reach asks
    for keyword in OUT_OF_REACH_KEYWORDS:
        if keyword in user_text_lower:
            resolution.out_of_reach_asks.append(user_text)
            resolution.rationale += (
                f" '{user_text}' requires Phase E (browser-based confirmation) "
                f"which is not yet implemented."
            )

    # Step 3: Target locations — infer from request method
    if request_model:
        if request_model.method == "GET":
            # GET has no body — body_json targets fall back to query/header
            if "body_json" in user_text_lower:
                resolution.target_locations = ["query", "header"]
                resolution.rationale += (
                    " GET request has no body — body_json target locations "
                    "fallback to query and header."
                )
            else:
                resolution.target_locations = ["query", "header"]
        elif request_model.method == "DELETE":
            # DELETE inherits A5's irreversibility gate
            resolution.rationale += (
                " DELETE method — payloads will inherit irreversibility gate."
            )
        else:
            resolution.target_locations = ["body_json", "query", "body_form", "header"]
    else:
        resolution.target_locations = ["body_json", "query", "body_form", "header"]

    # Step 4: Dialect hint from tech_stack
    if tech_stack and tech_stack.database:
        resolution.dialect_hint = tech_stack.database

    # Step 5: LLM enrichment (if runner provided and deterministic resolution found nothing)
    if runner and not resolution.resolved_categories:
        from nagapasha.utils.technique_categories import TECHNIQUE_CATEGORIES as TC
        schema = _intent_response_schema()
        try:
            raw = await runner.structured_call(
                prompt=(
                    f"Resolve this intent into technique-category keys. "
                    f"Valid categories: {sorted(TC.keys())}. "
                    f"User text: {user_text}"
                ),
                schema=schema,
            )
            # Belt-and-suspenders: validate against TECHNIQUE_CATEGORIES.keys()
            valid = set(TC.keys())
            resolved, rejected = [], []
            for cat in raw.get("resolved_categories", []):
                (resolved if cat in valid else rejected).append(cat)

            resolution.resolved_categories = resolved
            resolution.unsupported_asks = list(raw.get("unsupported_asks", [])) + rejected
            if rejected:
                import logging
                logging.getLogger(__name__).warning(
                    "LLM returned category outside TECHNIQUE_CATEGORIES: %s", rejected
                )
            resolution.target_locations = raw.get("target_locations")
            resolution.dialect_hint = raw.get("dialect_hint")
            resolution.out_of_reach_asks = raw.get("out_of_reach_asks", [])
            resolution.rationale = raw.get("rationale", "")
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                "LLM intent resolution failed: %s", e
            )
            resolution.rationale = f"LLM resolution failed: {e}"

    # Step 6: Unsupported asks — categories not yet implemented
    if not resolution.unsupported_asks and not resolution.resolved_categories:
        from nagapasha.utils.technique_categories import TECHNIQUE_CATEGORIES as TC
        # If user asked for something we don't have a category for, flag it
        resolution.unsupported_asks = [user_text]
        resolution.rationale = (
            f"No matching technique category found for: {user_text}. "
            f"Supported categories: {sorted(TC.keys())}"
        )

    return resolution
