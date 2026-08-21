"""Stage 8 — Fitter Agent.

Per-parameter payload placement and encoding decisions.

The critical nuance: joining, not just depth. For example, file=foo.jpg
+ ../../etc/passwd needs '/' glue — simply appending won't traverse
correctly.
"""

from __future__ import annotations

from typing import Any, Optional

from nagapasha.llm.runner import AnthropicRunner
from nagapasha.models.request_model import ParameterModel


FITTER_SYSTEM_PROMPT = """You are a security testing payload fitter. Given a parameter, its location in the HTTP request, an attack class, a payload, and the tech stack context, determine the optimal placement strategy.

Return ONLY a JSON object with these fields:
- parameter_name: the parameter name
- parameter_location: where the parameter lives
- placement_mode: full_replace, prefix, suffix, wrap, json_field_value, header_value, path_segment
- encoding: none, url, double_url, hex, unicode, base64
- glue_string: string needed to join payload with existing context
- pre_separator: character to prepend
- post_separator: character to append
- rationale: one-sentence explanation

Return ONLY the JSON object. No markdown fences, no commentary."""


class FitterError(Exception):
    """Raised when the Fitter agent fails."""


def run_fitter(
    parameter: ParameterModel,
    attack_class: str,
    payload: str,
    tech_stack: Optional[dict[str, Any]] = None,
    runner: Optional[AnthropicRunner] = None,
    timeout: int = 60,
    waf_detected: bool = False,
    waf_name: Optional[str] = None,
) -> dict[str, Any]:
    """Run the Fitter agent.

    Args:
        parameter: The parameter to fit the payload into.
        attack_class: The attack class.
        payload: The payload value.
        tech_stack: Detected tech stack.
        runner: AnthropicRunner instance. If None, uses heuristic fitting.
        timeout: Timeout in seconds.
        waf_detected: Whether a WAF was detected.
        waf_name: Name of the detected WAF (if any).

    Returns:
        Placement decision dict.
    """
    context = {
        "parameter_name": parameter.name,
        "parameter_location": parameter.location,
        "parameter_type": parameter.inferred_type,
        "attack_class": attack_class,
        "payload": payload,
        "tech_stack": tech_stack or {},
        "waf_detected": waf_detected,
        "waf_name": waf_name or "",
        "constraint": "Output ONLY valid JSON. No markdown fences. No commentary.",
    }

    if runner:
        try:
            response = runner.invoke(stage="fitter", context=context, timeout=timeout)
            if response.get("status") == "ok":
                data = response.get("data", {})
                if isinstance(data, dict) and "placement_mode" in data:
                    return data
        except Exception:
            pass

    # Fallback: heuristic fitting with tech stack awareness
    return _heuristic_fit(parameter, attack_class, payload, tech_stack or {}, waf_detected, waf_name)


def _heuristic_fit(
    parameter: ParameterModel,
    attack_class: str,
    payload: str,
    tech_stack: Optional[dict[str, Any]] = None,
    waf_detected: bool = False,
    waf_name: Optional[str] = None,
) -> dict[str, Any]:
    """Determine placement using heuristics when LLM is unavailable.

    Uses tech stack to select encoding and placement strategies:
    - PHP → single quote glue for SQLi
    - Node.js → JSON encoding for body params
    - WAF detected → use encoding tricks
    """
    location = parameter.location
    tech = tech_stack or {}
    framework = tech.get("framework", "").lower()
    language = tech.get("language", "").lower()
    placement_mode = "full_replace"
    encoding = "none"
    glue_string = ""
    pre_separator = ""
    post_separator = ""

    # Detect WAF-specific bypass needs
    waf_bypass_encoding = ""
    if waf_detected:
        if "cloudflare" in (waf_name or "").lower():
            waf_bypass_encoding = "double_url"
        elif "akamai" in (waf_name or "").lower():
            waf_bypass_encoding = "hex"
        elif "aws" in (waf_name or "").lower() or "imperva" in (waf_name or "").lower():
            waf_bypass_encoding = "unicode"

    if location == "query":
        placement_mode = "full_replace"
        # SQL payloads often need quote glue in query strings
        if "sql" in attack_class.lower():
            glue_string = "'"
            if "mongodb" in tech.get("database_hints", []) or "express" in framework:
                glue_string = ""  # NoSQL doesn't need quotes
        # SSRF payloads in query params
        if "ssrf" in attack_class.lower():
            glue_string = ""
        # XSS in query params
        if "xss" in attack_class.lower():
            encoding = waf_bypass_encoding or "url"
            pre_separator = '"'

    elif location == "body_json":
        placement_mode = "json_field_value"
        if "sql" in attack_class.lower():
            glue_string = "'"
            if "mongodb" in tech.get("database_hints", []) or "express" in framework:
                glue_string = ""  # NoSQL
        if "xss" in attack_class.lower():
            encoding = waf_bypass_encoding or "none"
        # JSON body payloads need proper JSON escaping
        if "xxe" in attack_class.lower() or "ssrf" in attack_class.lower():
            encoding = "none"  # Don't double-encode XML/URL in JSON

    elif location == "body_form":
        placement_mode = "full_replace"
        if "sql" in attack_class.lower():
            glue_string = "'"
        encoding = waf_bypass_encoding or encoding

    elif location == "header":
        placement_mode = "header_value"
        glue_string = ""
        # Custom headers often need no encoding
        if "ssrf" in attack_class.lower():
            encoding = "none"
        elif waf_detected:
            encoding = waf_bypass_encoding

    elif location == "cookie":
        placement_mode = "full_replace"
        encoding = waf_bypass_encoding or "url"

    elif location == "path":
        placement_mode = "path_segment"
        if "lfi" in attack_class.lower() or "traversal" in attack_class.lower():
            # Path traversal: payload like ../../etc/passwd needs '/' before traversal
            if payload.startswith(".."):
                glue_string = "/"
            else:
                glue_string = ""
        # PHP/LFI: use null byte for filter bypass
        if language == "php" and ("lfi" in attack_class.lower() or "traversal" in attack_class.lower()):
            pre_separator = "%00"  # Null byte to terminate PHP file inclusion
        encoding = "none"

    # Default: full replace with appropriate encoding
    rationale = (
        f"Heuristic fit for {parameter.name} ({location}) with {attack_class}"
        f"{' (WAF bypass)' if waf_detected else ''}"
    )

    return {
        "parameter_name": parameter.name,
        "parameter_location": location,
        "placement_mode": placement_mode,
        "encoding": encoding,
        "glue_string": glue_string,
        "pre_separator": pre_separator,
        "post_separator": post_separator,
        "rationale": rationale,
    }


def apply_placement(
    base_url: str,
    parameter: ParameterModel,
    placement: dict[str, Any],
    payload: str,
) -> str:
    """Apply a placement decision to construct the modified URL.

    Args:
        base_url: The original base URL.
        parameter: The parameter being modified.
        placement: The fitter's placement decision.
        payload: The payload to inject.

    Returns:
        The modified URL string.
    """
    import urllib.parse

    placement_mode = placement.get("placement_mode", "full_replace")
    glue = placement.get("glue_string", "")
    pre = placement.get("pre_separator", "")
    post = placement.get("post_separator", "")

    if placement_mode == "full_replace":
        if parameter.location == "query":
            return _replace_query_param(base_url, parameter.name, payload)
        elif parameter.location == "path":
            return _replace_path_segment(base_url, parameter.name, payload)
        else:
            return base_url  # Body/header params handled elsewhere

    elif placement_mode == "prefix":
        if parameter.location == "query":
            return _prefix_query_param(base_url, parameter.name, glue + payload)
        return base_url

    elif placement_mode == "suffix":
        if parameter.location == "query":
            return _suffix_query_param(base_url, parameter.name, payload + glue)
        return base_url

    elif placement_mode == "wrap":
        if parameter.location == "query":
            return _wrap_query_param(
                base_url, parameter.name, pre + payload + post
            )
        return base_url

    return base_url


def _replace_query_param(url: str, param_name: str, value: str) -> str:
    """Replace a query parameter value in a URL."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param_name] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _prefix_query_param(url: str, param_name: str, value: str) -> str:
    """Prepend a value to a query parameter."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    current = qs.get(param_name, [""])[0]
    qs[param_name] = [value + current]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _suffix_query_param(url: str, param_name: str, value: str) -> str:
    """Append a value to a query parameter."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    current = qs.get(param_name, [""])[0]
    qs[param_name] = [current + value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _wrap_query_param(url: str, param_name: str, value: str) -> str:
    """Wrap a query parameter value with pre/post separators."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param_name] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _replace_path_segment(url: str, param_name: str, value: str) -> str:
    """Replace a path segment in a URL."""
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(url)
    parts = parsed.path.strip("/").split("/")
    for i, part in enumerate(parts):
        if part == param_name or (param_name and param_name in part):
            parts[i] = value
            break
    new_path = "/" + "/".join(parts)
    return urlunparse(parsed._replace(path=new_path))
