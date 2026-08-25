"""Stage 13 — Target deduplication.

Merges and deduplicates discovered endpoints from multiple sources
(e.g., OpenAPI, crawl, manual targets) into a flat, deduplicated list
ready for scanning.

Deduplication logic:
  - Normalize paths (strip trailing slash, lowercase)
  - Dedup by (method.upper(), normalized_path)
  - Preserve first occurrence (OpenAPI before crawl)
  - Merge parameters by name+location
  - Merge risk_tags (union of all tags)
  - Merge body_schema (prefer first non-None)
  - Merge base_url (prefer non-None)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any

from nagapasha.models.request_model import ParameterModel


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class DeduplicationResult:
    """Structured output of deduplicating discovered endpoints.

    Attributes:
        endpoints: Deduplicated endpoints ready for scanning
        original_count: Number of endpoints before deduplication
        deduped_count: Number of endpoints after deduplication
        removed_count: Number of duplicate endpoints removed
        warnings: Non-fatal issues encountered during deduplication
    """

    endpoints: list["DiscoveredEndpoint"] = field(default_factory=list)
    original_count: int = 0
    deduped_count: int = 0
    removed_count: int = 0
    warnings: list[str] = field(default_factory=list)


# Re-import DiscoveredEndpoint from B1 (stage09) to avoid circular imports
# We use string typing to avoid import at module load time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nagapasha.stages.stage09_openapi import DiscoveredEndpoint
else:
    # At runtime, we'll accept any dataclass with the same interface
    DiscoveredEndpoint = None


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_path(path: str) -> str:
    """Normalize a path for deduplication comparison.

    - Strip trailing slash (except for root "/")
    - Lowercase

    Args:
        path: Raw path string (e.g. "/users/", "/Users/123")

    Returns:
        Normalized path string (e.g. "/users", "/users/123")
    """
    path = path.rstrip("/") if path != "/" else "/"
    return path.lower()


# ---------------------------------------------------------------------------
# Deduplication logic
# ---------------------------------------------------------------------------


def deduplicate_endpoints(
    endpoints: list[Any],
) -> DeduplicationResult:
    """Deduplicate a list of discovered endpoints.

    Args:
        endpoints: List of DiscoveredEndpoint objects from various sources

    Returns:
        DeduplicationResult with deduplicated endpoints
    """
    result = DeduplicationResult()
    result.original_count = len(endpoints)

    if not endpoints:
        result.deduped_count = 0
        result.removed_count = 0
        return result

    seen: dict[tuple[str, str], int] = {}  # (method, normalized_path) -> index
    deduped: list[Any] = []

    for endpoint in endpoints:
        # Normalize path for deduplication key
        norm_path = normalize_path(endpoint.path_template)
        method = endpoint.method.upper()
        key = (method, norm_path)

        if key in seen:
            # Duplicate found — merge parameters
            merged_index = seen[key]
            merge_endpoint(deduped[merged_index], endpoint)
            result.removed_count += 1
            result.warnings.append(
                f"Removed duplicate: {endpoint.method} {endpoint.path_template}"
            )
        else:
            # First occurrence — keep it
            seen[key] = len(deduped)
            deduped.append(endpoint)

    result.endpoints = deduped
    result.deduped_count = len(deduped)

    return result


def merge_endpoint(
    primary: Any,
    duplicate: Any,
) -> None:
    """Merge a duplicate endpoint into the primary endpoint.

    Merges parameters, risk_tags, body_schema, base_url.

    Args:
        primary: The primary (kept) endpoint
        duplicate: The duplicate endpoint to merge into primary
    """
    # Merge parameters (union by name+location)
    primary_param_keys = {(p.name, p.location) for p in primary.parameters}
    for param in duplicate.parameters:
        if (param.name, param.location) not in primary_param_keys:
            primary.parameters.append(param)
            primary_param_keys.add((param.name, param.location))

    # Merge risk_tags (union)
    for tag in duplicate.risk_tags:
        if tag not in primary.risk_tags:
            primary.risk_tags.append(tag)

    # Merge body_schema (prefer first non-None)
    if primary.body_schema is None and duplicate.body_schema is not None:
        primary.body_schema = duplicate.body_schema

    # Merge base_url (prefer first non-None)
    if primary.base_url is None and duplicate.base_url is not None:
        primary.base_url = duplicate.base_url

    # Update risk_tags if any
    if duplicate.risk_tags:
        primary.risk_tags = list(set(primary.risk_tags) | set(duplicate.risk_tags))
