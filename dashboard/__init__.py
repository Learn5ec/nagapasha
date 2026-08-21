"""Dashboard package for nagapasha.

Provides a FastAPI-based web interface for driving the nagapasha pipeline.
"""

from dashboard.events import EventBus
from dashboard.runs import ActiveRuns, ActiveRun

# Module-scoped singletons shared across the dashboard package
event_bus = EventBus()
active_runs = ActiveRuns()

__all__ = ["event_bus", "active_runs", "EventBus", "ActiveRuns", "ActiveRun"]
