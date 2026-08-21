"""PII/secret redaction for Stage 13.

This module provides redaction of personally identifiable information (PII)
and secrets from captured evidence before storage or reporting.

Redaction patterns include:
- Email addresses
- Phone numbers
- SSN (Social Security Numbers)
- Credit card numbers
- API keys
- JWT tokens
- Session tokens
- Passwords
- Private keys

Usage:
    redacted = redact_text("User email: john@example.com")
    # Result: "User email: [REDACTED]"
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Redaction patterns
REDACTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b")),
    ("ssn", re.compile(r"\b(?:\d{3}-\d{2}-\d{4})\b")),
    ("credit_card", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("api_key", re.compile(r"(?:api_key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9]{32,}['\"]?")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("session_token", re.compile(r"(?:session|sid|token)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?")),
    ("password", re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?.+['\"]?")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

# Replacement text
REDACTION_REPLACEMENT = "[REDACTED]"


def redact_text(text: str) -> str:
    """Redact PII and secrets from text.

    Args:
        text: Input text to redact

    Returns:
        Redacted text with PII/secrets replaced
    """
    if not text or not isinstance(text, str):
        return text

    redacted = text
    for pattern_name, pattern in REDACTION_PATTERNS:
        redacted = pattern.sub(REDACTION_REPLACEMENT, redacted)

    return redacted


def redact_dict(data: Any) -> Any:
    """Recursively redact PII/secrets from a dictionary.

    Args:
        data: Input dictionary or value

    Returns:
        Redacted dictionary
    """
    if isinstance(data, dict):
        return {
            key: redact_dict(value)
            for key, value in data.items()
        }
    elif isinstance(data, list):
        return [redact_dict(item) for item in data]
    elif isinstance(data, str):
        return redact_text(data)
    return data


def redact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Redact PII/secrets from evidence dict.

    Args:
        evidence: Evidence dictionary with request/response data

    Returns:
        Redacted evidence
    """
    return redact_dict(evidence)


def load_redaction_rules(path: Path) -> None:
    """Load custom redaction rules from YAML file.

    Args:
        path: Path to .redact.yaml file
    """
    if not path.exists():
        return

    try:
        import yaml
        rules = yaml.safe_load(path.read_text()) or {}
        if isinstance(rules, dict):
            for name, pattern_str in rules.items():
                if isinstance(pattern_str, str):
                    try:
                        pattern = re.compile(pattern_str)
                        REDACTION_PATTERNS.append((name, pattern))
                        logger.info(f"Loaded redaction rule: {name}")
                    except re.error as e:
                        logger.warning(f"Invalid redaction pattern '{name}': {e}")
    except Exception as e:
        logger.warning(f"Failed to load redaction rules: {e}")


def create_redacted_file(
    data: Any,
    output_path: Path,
    fmt: str = "json",
) -> Path:
    """Create a redacted version of data and save to file.

    Args:
        data: Input data (dict, list, or string)
        output_path: Output file path
        fmt: Output format (json, yaml)

    Returns:
        Path to redacted file
    """
    redacted = redact_dict(data) if not isinstance(data, str) else redact_text(data)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        import json
        if isinstance(redacted, (dict, list)):
            output_path.write_text(json.dumps(redacted, indent=2))
        else:
            output_path.write_text(str(redacted))
    elif fmt == "yaml":
        import yaml
        output_path.write_text(yaml.dump(redacted, default_flow_style=False))
    else:
        output_path.write_text(str(redacted))

    logger.info(f"Redacted data saved to: {output_path}")
    return output_path
