"""TTY-aware confirmation helpers for destructive payloads.

This module provides confirmation logic for destructive payloads (Stage 8.5):
- Interactive mode: prompt user with payload preview
- Non-interactive mode: check config flags or environment variables
- Constrained probe variants: fire safe test before full payload

The goal is to prevent accidental data loss or system damage from destructive
attacks like RCE, deserialization, or XXE-write.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Destructive attack classes that require confirmation
DESTRUCTIVE_CLASSES = {
    "rce",
    "command_injection",
    "deserialization",
    "xxe_write",
    "sqli_write",
    "ssrf_write",
}

# Benign attack classes (don't require confirmation)
BENIGN_CLASSES = {
    "sql_injection",
    "xss",
    "lfi",
    "idor",
    "ssrf_read",
    "path_traversal",
    "generic_injection",
    "nosql_injection",
}


def is_destructive_class(attack_class: str) -> bool:
    """Check if an attack class is destructive.

    Args:
        attack_class: Attack class name

    Returns:
        True if attack class is destructive
    """
    return attack_class in DESTRUCTIVE_CLASSES


def confirm_destructive(
    payload_description: str,
    payload_preview: str,
    interactive: bool,
    allow_destructive: bool = False,
    env_var: str = "NAGAPASHA_ALLOW_DESTRUCTIVE",
) -> bool:
    """Confirm destructive payload with user or config.

    Args:
        payload_description: Human-readable description of the payload
        payload_preview: Preview of the payload (truncated)
        interactive: Whether running in interactive mode (TTY)
        allow_destructive: Whether destructive payloads are pre-allowed
        env_var: Environment variable name for non-interactive allow

    Returns:
        True if payload is approved, False if denied/skipped
    """
    # Check if destructive is pre-allowed via config
    if allow_destructive:
        logger.info(f"Destructive pre-allowed: {payload_description}")
        return True

    # Check environment variable for non-interactive allow
    if os.environ.get(env_var):
        logger.info(f"Destructive allowed via {env_var}: {payload_description}")
        return True

    if interactive:
        # Interactive mode: prompt user
        return _prompt_user(payload_description, payload_preview)
    else:
        # Non-interactive: fail closed (deny)
        logger.warning(
            f"Destructive payload denied in non-interactive mode: "
            f"{payload_description} "
            f"(set {env_var}=1 or use --allow-destructive to override)"
        )
        return False


def _prompt_user(payload_description: str, payload_preview: str) -> bool:
    """Prompt user for confirmation.

    Args:
        payload_description: Human-readable description
        payload_preview: Payload preview (truncated)

    Returns:
        True if user approves, False if denied
    """
    # Try rich first (better UX)
    try:
        from rich.prompt import Prompt

        print(f"\n[bold red]⚠️  Destructive payload detected[/bold red]")
        print(f"  Description: {payload_description}")
        print(f"  Preview: {payload_preview[:60]}...")
        answer = Prompt.ask(
            "Fire destructive payload? [y/N]",
            default="n",
        )
        return answer.lower() == "y"
    except ImportError:
        pass

    # Fallback to input()
    try:
        print(f"\n⚠️  Destructive payload detected")
        print(f"  Description: {payload_description}")
        print(f"  Preview: {payload_preview[:60]}...")
        answer = input("Fire destructive payload? [y/N] ")
        return answer.lower() == "y"
    except EOFError:
        # No stdin available (e.g., piped input)
        logger.warning("No stdin available — denying destructive payload")
        return False


def suggest_probe_variant(attack_class: str) -> Optional[str]:
    """Suggest a constrained probe variant for a destructive attack.

    Args:
        attack_class: Attack class name

    Returns:
        Safe probe payload, or None if no probe available
    """
    if attack_class == "rce" or attack_class == "command_injection":
        return "sleep(5)"
    elif attack_class == "xxe_write":
        return "file:///etc/passwd"  # Read-only variant
    elif attack_class == "sqli_write":
        return "SLEEP(5)"  # MySQL timing-based read-only
    elif attack_class == "ssrf_write":
        return "http://127.0.0.1:1"  # Internal host check
    elif attack_class == "deserialization":
        return None  # No safe probe for deserialization

    return None


def run_probe(
    payload_description: str,
    probe_payload: str,
    interactive: bool,
) -> bool:
    """Run a constrained probe and ask for confirmation if successful.

    Args:
        payload_description: Human-readable description
        probe_payload: Safe probe payload to fire
        interactive: Whether running in interactive mode

    Returns:
        True if full payload should be fired, False if skipped
    """
    # In non-interactive mode, skip if probe is ambiguous
    if not interactive:
        logger.debug(f"Skipping probe in non-interactive mode: {payload_description}")
        return False

    # Probe succeeded — ask for confirmation to fire full payload
    try:
        from rich.prompt import Prompt

        print(f"\n[bold yellow]Probe succeeded:[/bold yellow] {payload_description}")
        print(f"  Probe payload: {probe_payload}")
        answer = Prompt.ask(
            "Fire full destructive payload? [y/N]",
            default="n",
        )
        return answer.lower() == "y"
    except ImportError:
        pass

    try:
        print(f"\nProbe succeeded: {payload_description}")
        print(f"  Probe payload: {probe_payload}")
        answer = input("Fire full destructive payload? [y/N] ")
        return answer.lower() == "y"
    except EOFError:
        logger.warning("No stdin available — skipping destructive payload")
        return False
