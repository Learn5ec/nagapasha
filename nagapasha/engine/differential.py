"""Generalized boolean-blind (differential) detection.

Compares two logically-opposite payload responses (e.g. true-condition vs
false-condition) against each other — not against baseline. If they differ,
that's a signal that the backend interpreted the payload differently.

This is dialect-agnostic: it works the same whether the pair is SQL boolean
logic (1 AND 1=1 vs 1 AND 1=2), NoSQL operator injection ({"$ne": null} vs
{"$eq": ""}), or template-injection truthy/falsy pairs. The detection
principle ("do these two logically-opposite payloads produce different
responses?") is what generalizes, not any specific string.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from nagapasha.engine.diff import BaselineFingerprint


@dataclass
class DeltaSignal:
    """Signal from a differential comparison."""

    detected: bool = False
    description: str = ""
    significance: float = 0.0  # 0.0 - 1.0
    delta_details: list[str] = field(default_factory=list)


def run_differential_pair(
    true_body: str,
    false_body: str,
    true_status: int,
    false_status: int,
    true_headers: Optional[dict[str, str]] = None,
    false_headers: Optional[dict[str, str]] = None,
) -> DeltaSignal:
    """Compare true-condition vs false-condition response.

    Returns a DeltaSignal indicating whether the two responses differ in a
    meaningful way that suggests the backend processed the payloads differently.

    Args:
        true_body: Body of the "true" condition response.
        false_body: Body of the "false" condition response.
        true_status: Status code of true response.
        false_status: Status code of false response.
        true_headers: Headers of true response (optional).
        false_headers: Headers of false response (optional).

    Returns:
        DeltaSignal with detected=True if responses differ meaningfully.
    """
    signal = DeltaSignal()

    # Check status code difference
    if true_status != false_status:
        signal.detected = True
        signal.significance = 0.80
        signal.delta_details.append(
            f"status-differential: {true_status} vs {false_status}"
        )
        signal.description = (
            f"True ({true_status}) and false ({false_status}) conditions "
            f"produced different status codes"
        )

    # Check body difference (using hash comparison for efficiency)
    if true_body != false_body:
        import hashlib
        true_hash = hashlib.sha256(true_body.encode("utf-8", errors="replace")).hexdigest()
        false_hash = hashlib.sha256(false_body.encode("utf-8", errors="replace")).hexdigest()
        if true_hash != false_hash:
            signal.detected = True
            if signal.significance < 0.50:
                signal.significance = 0.50
            signal.delta_details.append(
                "body-differential: true and false responses differ"
            )
            signal.description = (
                "True and false conditions produced different response bodies"
            )

    # Check headers difference
    if true_headers and false_headers:
        true_header_set = frozenset(k.lower().strip() for k in true_headers.keys())
        false_header_set = frozenset(k.lower().strip() for k in false_headers.keys())
        if true_header_set != false_header_set:
            signal.detected = True
            if signal.significance < 0.40:
                signal.significance = 0.40
            signal.delta_details.append(
                "header-differential: true and false responses have different headers"
            )

    return signal
