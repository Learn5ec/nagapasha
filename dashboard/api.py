"""REST API endpoints for the nagapasha dashboard.

Provides CRUD operations for engagements and findings.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from nagapasha.db.schema import EngagementStore
from dashboard import active_runs

router = APIRouter()

# Shared database instance
_db = EngagementStore()


# ---------------------------------------------------------------------------
# Request/response schemas
# ---------------------------------------------------------------------------

class EngagementCreate(BaseModel):
    """Create a new engagement via the dashboard."""

    target_host: str
    target_url: str
    method: str = "GET"
    notes: Optional[str] = None


class EngagementResponse(BaseModel):
    """Engagement data returned by the API."""

    id: str
    created_at: str
    target_host: str
    target_url: str
    method: str
    scope_confirmed: int
    status: str
    rate_limit_pps: Optional[float] = None
    jwt_expires_at: Optional[float] = None
    tech_stack_json: Optional[str] = None
    generated_script_path: Optional[str] = None
    notes: Optional[str] = None


class FindingResponse(BaseModel):
    """A finding returned by the API."""

    id: str
    engagement_id: str
    created_at: str
    parameter_name: str
    attack_class: str
    payload: str
    placement_mode: str
    encoding: Optional[str] = None
    severity: Optional[str] = None
    evidence_req: Optional[str] = None
    evidence_resp: Optional[str] = None
    confidence: Optional[float] = None
    specialist_verdict: Optional[str] = None
    specialist_notes: Optional[str] = None
    wstg_reference: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/engagements", response_model=list[dict])
def list_engagements():
    """List all engagements, ordered by most recent first."""
    return _db.get_engagements()


@router.get("/engagements/{engagement_id}", response_model=dict)
def get_engagement(engagement_id: str):
    """Get a single engagement by ID."""
    engagement = _db.get_engagement(engagement_id)
    if not engagement:
        return {"error": "Engagement not found"}
    return engagement


@router.post("/engagements", response_model=dict)
def create_engagement(data: EngagementCreate):
    """Create a new engagement."""
    eid = _db.create_engagement(
        target_host=data.target_host,
        target_url=data.target_url,
        method=data.method,
        scope_confirmed=True,
        notes=data.notes,
    )
    _db.update_engagement_status(eid, "planning")
    return {"engagement_id": eid}


@router.get("/engagements/{engagement_id}/findings", response_model=list[dict])
def list_findings(engagement_id: str):
    """List all findings for an engagement, ordered by severity."""
    return _db.get_findings(engagement_id)


@router.get("/live/{engagement_id}")
def get_live_status(engagement_id: str):
    """Get the live execution state for an engagement."""
    run = active_runs.get(engagement_id)
    if not run:
        return {"error": "Run not found"}
    return run.to_dict()
