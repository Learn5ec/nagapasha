"""Stage 5 — Strategist Agent.

LLM agent that analyzes the request + baseline + tech stack to produce
ranked attack candidates per parameter.
"""

from __future__ import annotations

from typing import Any, Optional

from nagapasha.llm.runner import AnthropicRunner
from nagapasha.models.request_model import RequestModel
from nagapasha.utils.confirm import is_destructive_class


# Location priority for parameter ordering (lower = higher priority)
LOCATION_PRIORITY = {
    "body_json": 1,
    "path": 2,
    "cookie": 3,
    "header": 4,
    "query": 5,
    "body_form": 6,
    "body_multipart": 7,
}


def _get_param_location(request_model: RequestModel, param_idx: int) -> str:
    """Get the location of a parameter by index."""
    if 0 <= param_idx < len(request_model.parameters):
        return request_model.parameters[param_idx].location
    return "query"


STRATEGIST_SYSTEM_PROMPT = """You are a security testing strategist. Given an HTTP request, its baseline response, and the detected tech stack, produce ranked attack candidates per parameter.

For each parameter that can be fuzzed, recommend specific attack classes (e.g., SQLi, XSS, LFI, IDOR, SSRF, path traversal, command injection, XXE).

Output ONLY a JSON array of objects with these fields:
- parameter_index: integer index into the parameters list
- attack_class: string name of the attack class
- rationale: one-sentence explanation
- confidence: "high", "medium", or "low"
- wstg_reference: OWASP WSTG section
- recommended_payload_tags: list of payload category tags
- parameter_name: the parameter name
- parameter_type: the parameter's inferred type

Return the JSON array only, no markdown fences, no commentary."""


class StrategistError(Exception):
    """Raised when the Strategist agent fails."""


def run_strategist(
    request_model: RequestModel,
    baseline_fingerprint: Optional[dict[str, Any]] = None,
    confirmed_tech_stack: Optional[dict[str, Any]] = None,
    runner: Optional[AnthropicRunner] = None,
    timeout: int = 120,
    waf_detected: bool = False,
    waf_name: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Run the Strategist agent.

    Args:
        request_model: The RequestModel with parameters.
        baseline_fingerprint: Baseline response fingerprint.
        confirmed_tech_stack: Confirmed tech stack from Stage 4.
        runner: AnthropicRunner instance. If None, creates one.
        timeout: Timeout in seconds.
        waf_detected: Whether a WAF was detected in recon.
        waf_name: Name of the detected WAF (if any).

    Returns:
        List of attack candidate dicts.

    Raises:
        StrategistError: If the agent fails.
    """
    if runner is None:
        runner = AnthropicRunner()

    context = {
        "method": request_model.method,
        "url": request_model.url,
        "base_url": request_model.base_url,
        "parameters": [p.to_dict() for p in request_model.parameters],
        "baseline": baseline_fingerprint or {},
        "tech_stack": confirmed_tech_stack or {},
        "headers": request_model.headers,
        "body": request_model.body,
        "body_type": request_model.body_type,
        "constraint": "Output ONLY valid JSON. No markdown fences. No commentary.",
    }

    try:
        response = runner.invoke(
            stage="strategist",
            context=context,
            timeout=timeout,
        )
    except Exception as e:
        # Fallback: generate default candidates without LLM
        return _default_candidates(request_model, confirmed_tech_stack or {}, waf_detected, waf_name)

    if response.get("status") != "ok":
        return _default_candidates(request_model, confirmed_tech_stack or {}, waf_detected, waf_name)

    data = response.get("data", [])
    if not isinstance(data, list):
        return _default_candidates(request_model, confirmed_tech_stack or {}, waf_detected, waf_name)

    # Validate shape — accept any candidate with parameter_index and attack_class
    valid = []
    for candidate in data:
        if (
            isinstance(candidate, dict)
            and "parameter_index" in candidate
            and "attack_class" in candidate
        ):
            # Normalize priority: default to location-based if not specified
            if "priority" not in candidate:
                loc = _get_param_location(request_model, candidate["parameter_index"])
                candidate["priority"] = LOCATION_PRIORITY.get(loc, 99)

            # Tag destructive flag if not provided by LLM
            if "destructive" not in candidate:
                candidate["destructive"] = is_destructive_class(candidate["attack_class"])

            valid.append(candidate)

    return valid if valid else _default_candidates(request_model, confirmed_tech_stack or {}, waf_detected, waf_name)


def _default_candidates(
    request_model: RequestModel,
    confirmed_tech_stack: dict[str, Any],
    waf_detected: bool = False,
    waf_name: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Generate default attack candidates without LLM.

    This is the fallback when the LLM is unavailable. Uses tech stack
    to select the most relevant attack classes.

    Tags each candidate with a `destructive` flag based on the attack class:
    - Destructive classes (RCE, deserialization, XXE-write, etc.) require
      human confirmation before firing (Stage 8.5).
    - Benign classes (SQLi, XSS, LFI, etc.) are allowed without confirmation.
    """
    candidates = []

    for idx, param in enumerate(request_model.parameters):
        if not param.is_fuzz_target or param.do_not_fuzz:
            continue

        attack_class = _guess_attack_class(param, confirmed_tech_stack, waf_detected, waf_name)
        if not attack_class:
            continue

        candidates.append({
            "parameter_index": idx,
            "attack_class": attack_class,
            "rationale": f"Default candidate for {param.name} ({param.location})",
            "confidence": "low",
            "wstg_reference": "WSTG-INPV-08",
            "recommended_payload_tags": [attack_class.replace(" ", "_")],
            "parameter_name": param.name,
            "parameter_type": param.inferred_type,
            "destructive": is_destructive_class(attack_class),
        })

    return candidates


def _guess_attack_class(
    param,
    confirmed_tech_stack: Optional[dict[str, Any]] = None,
    waf_detected: bool = False,
    waf_name: Optional[str] = None,
) -> Optional[str]:
    """Heuristically guess the most likely attack class for a parameter.

    Uses detected tech stack to prioritize attack classes. For example:
    - PHP → SQLi, LFI
    - Node.js → XSS, SSRF
    - Java → XXE, deserialization
    - Database hints → SQLi/NoSQLi
    - WAF detected → include bypass payloads
    """
    name_lower = param.name.lower()
    loc = param.location
    tech = confirmed_tech_stack or {}

    # Detect tech stack components
    framework = tech.get("framework", "").lower()
    language = tech.get("language", "").lower()
    web_server = tech.get("web_server", "").lower()
    db_hints = tech.get("database_hints", [])
    session_mgmt = tech.get("session_management", [])

    # Priority 1: JSON body parameters (highest value, least noisy)
    if loc == "body_json":
        # JSON body is the best target — most attacks succeed here
        if any(kw in name_lower for kw in ("id", "user", "name", "search", "query", "filter")):
            return "sql_injection"
        if "file" in name_lower or "path" in name_lower or "doc" in name_lower:
            return "lfi"
        # JSON body with URL-like values → SSRF
        if param.inferred_type == "free_text":
            return "ssrf"
        # Default for JSON body
        return "xss"  # XSS is most common in JSON body parameters

    # Priority 2: URL path parameters
    if loc == "path":
        if any(kw in name_lower for kw in ("file", "path", "dir", "folder", "doc", "page")):
            return "path_traversal"
        return "path_traversal"  # Path params are always traversal targets

    # Priority 3: Cookie/Auth headers (IDOR, session manipulation)
    if loc == "cookie":
        if any(c in session_mgmt for c in ["session", "auth", "token"]):
            return "idor"
        return "idor"  # Cookies are prime for IDOR

    if loc == "header":
        if "user" in name_lower or "id" in name_lower or "auth" in name_lower:
            return "idor"
        if "x-" in name_lower:
            return "ssrf"  # Custom headers often accepted in SSRF

    # Priority 4: Query string and form body
    if loc in ("query", "body_form"):
        if any(kw in name_lower for kw in ("id", "user", "name", "search", "query", "filter",
                                             "sort", "order", "group", "where", "select")):
            # Database hints strongly suggest SQLi
            if db_hints or language == "php" or framework in ("django", "flask", "rails", "laravel"):
                return "sql_injection"
            if "mongodb" in db_hints or framework in ("express", "fastify"):
                return "nosql_injection"
            return "sql_injection"  # Default for query params with SQL-like names
        if any(kw in name_lower for kw in ("file", "path", "dir", "folder", "doc", "page", "include")):
            if language == "php":
                return "lfi"
            return "path_traversal"
        if param.inferred_type == "free_text":
            return "xss"
        return "generic_injection"

    # Fallback
    if loc in ("body_json", "body_form"):
        return "xss"
    if loc == "query":
        return "generic_injection"

    return None
