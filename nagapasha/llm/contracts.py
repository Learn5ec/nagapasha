"""JSON contracts for claude-cli agent stages.

Each agent stage has a fixed input/output contract. These TypedDicts
validate the shape of data before sending to the LLM.
"""

from __future__ import annotations

from typing import Any, Optional, TypedDict


class StrategistInput(TypedDict, total=False):
    """Input to the Strategist agent (Stage 5)."""

    role: str               # always "agent"
    stage: str              # always "strategist"
    context: dict[str, Any]  # RequestModel + baseline + tech stack
    constraint: str         # instruction for JSON-only output


class StrategistOutput(TypedDict, total=False):
    """Output from the Strategist agent."""

    status: str             # "ok" or "error"
    data: list[dict[str, Any]]  # list of attack candidates
    tokens_used: dict[str, int]  # input/output token counts


class LibrarianInput(TypedDict, total=False):
    """Input to the Librarian agent (Stage 7)."""

    role: str
    stage: str              # always "librarian"
    context: dict[str, Any]  # attack classes + tech stack
    constraint: str


class LibrarianOutput(TypedDict, total=False):
    """Output from the Librarian agent."""

    status: str
    data: dict[str, Any]    # payload files and technique notes
    tokens_used: dict[str, int]


class FitterInput(TypedDict, total=False):
    """Input to the Fitter agent (Stage 8)."""

    role: str
    stage: str              # always "fitter"
    context: dict[str, Any]  # parameter + attack class + payload + tech
    constraint: str


class FitterOutput(TypedDict, total=False):
    """Output from the Fitter agent."""

    status: str
    data: dict[str, Any]    # placement_mode, encoding, glue_string
    tokens_used: dict[str, int]


class SpecialistInput(TypedDict, total=False):
    """Input to the Specialist agent (Stage 11)."""

    role: str
    stage: str              # always "specialist"
    context: dict[str, Any]  # near_miss details + technique KB
    constraint: str


class SpecialistOutput(TypedDict, total=False):
    """Output from the Specialist agent."""

    status: str
    data: dict[str, Any]    # confirmed, verdict, evidence
    tokens_used: dict[str, int]


# All valid stage names
VALID_STAGES = {"strategist", "librarian", "fitter", "specialist"}


def validate_stage(stage: str) -> bool:
    """Check if a stage name is valid."""
    return stage in VALID_STAGES
