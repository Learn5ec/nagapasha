"""Shared data models — the spine of the tool.

Every stage consumes/produces these dataclasses. Each stage only reads the
fields it needs and writes to its own fields. Later stages compose earlier
stages' outputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional
import json


# ---------------------------------------------------------------------------
# Parameter
# ---------------------------------------------------------------------------

PARAM_LOCATIONS = ("query", "body_json", "body_form", "body_multipart",
                   "header", "cookie", "path")

PARAM_TYPES = ("int", "uuid", "email", "filename", "date", "boolean",
               "free_text")


@dataclass
class ParameterModel:
    """A single extractable parameter from an HTTP request."""

    name: str
    location: str               # PARAM_LOCATIONS
    inferred_type: str          # PARAM_TYPES
    raw_value: str              # original value from the request

    is_fuzz_target: bool = False        # set by human in Stage 3
    do_not_fuzz: bool = True            # default-true for auth params
    tech_stack_context: Optional[str] = None  # filled by Stage 4

    # --- helpers -----------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ParameterModel":
        return cls(**data)


# ---------------------------------------------------------------------------
# Request (the growing spine)
# ---------------------------------------------------------------------------

@dataclass
class RequestModel:
    """
    Spine of the tool. Every stage consumes/produces this (or a superset).
    """

    # ---- Stage 1 outputs --------------------------------------------------
    method: str
    url: str
    base_url: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    body_type: Optional[str] = None       # "json", "form", "multipart"
    query_params: dict[str, str] = field(default_factory=dict)
    path_segments: list[str] = field(default_factory=list)
    parameters: list[ParameterModel] = field(default_factory=list)

    # ---- Stage 2 outputs --------------------------------------------------
    auth_valid: Optional[bool] = None
    jwt_info: Optional[dict[str, Any]] = None
    baseline_fingerprint: Optional[dict[str, Any]] = None
    rate_limit_pps: Optional[float] = None
    rate_limit_config: Optional[dict[str, Any]] = None

    # ---- Stage 4 outputs --------------------------------------------------
    confirmed_tech_stack: Optional[dict[str, Any]] = None

    # ---- Stage 5-8 outputs (attack specs per-parameter) ------------------
    attack_specs: list[dict[str, Any]] = field(default_factory=list)

    # ---- Stage 10 outputs -------------------------------------------------
    triage_results: list[dict[str, Any]] = field(default_factory=list)

    # ---- Run-time metadata ------------------------------------------------
    engagement_id: Optional[str] = None
    run_start: Optional[str] = None
    scope_confirmed: bool = False

    # --- helpers -----------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain JSON-compatible dict."""
        return _request_to_dict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RequestModel":
        """Deserialize from a plain dict."""
        # Use .get() to avoid mutating the input dict
        params = data.get("parameters", [])
        parameters = [ParameterModel.from_dict(p) for p in params]
        return cls(parameters=parameters, **data)


def _request_to_dict(obj: RequestModel) -> dict[str, Any]:
    """Custom serializer that converts ParameterModel list to dicts."""
    d = asdict(obj)
    # asdict should handle ParameterModel too, but be safe
    d["parameters"] = [p.to_dict() if isinstance(p, ParameterModel)
                       else p for p in d.get("parameters", [])]
    return d
