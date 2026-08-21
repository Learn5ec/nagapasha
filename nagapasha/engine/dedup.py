"""Payload deduplication module.

Avoids firing identical payloads against different parameters by using
hash-based deduplication on (parameter_name, parameter_location, payload).
"""

from __future__ import annotations

from typing import Dict, Set

from nagapasha.engine.payload_loop import PayloadCandidate


def deduplicate_payloads(
    payloads: list[PayloadCandidate],
) -> list[PayloadCandidate]:
    """Remove duplicate payloads based on parameter and payload content.

    Args:
        payloads: List of PayloadCandidate objects.

    Returns:
        Deduplicated list of PayloadCandidate objects (first occurrence kept).
    """
    seen: Set[tuple] = set()
    unique: list[PayloadCandidate] = []

    for candidate in payloads:
        # Create a unique key from parameter name, location, and payload
        key = (
            candidate.parameter.name,
            candidate.parameter.location,
            candidate.payload,
        )

        if key not in seen:
            seen.add(key)
            unique.append(candidate)

    return unique


def deduplication_stats(
    original_count: int,
    deduplicated_count: int,
) -> dict:
    """Calculate deduplication statistics.

    Args:
        original_count: Number of payloads before deduplication.
        deduplicated_count: Number of payloads after deduplication.

    Returns:
        Stats dict with original_count, deduplicated_count, removed_count,
        and reduction_percent.
    """
    removed_count = original_count - deduplicated_count
    reduction_percent = (
        (removed_count / original_count * 100)
        if original_count > 0 else 0
    )

    return {
        "original_count": original_count,
        "deduplicated_count": deduplicated_count,
        "removed_count": removed_count,
        "reduction_percent": round(reduction_percent, 2),
    }
