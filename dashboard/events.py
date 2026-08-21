"""In-memory event bus for the dashboard.

Pub/sub pattern: subscribers register for event types, publishers dispatch
data to all subscribers. Used to push live run updates to WebSocket clients.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional


class EventBus:
    """Simple pub/sub event bus.

    Subscribers are called synchronously when events are published.
    Async callbacks are scheduled as tasks.
    """

    def __init__(self) -> None:
        self._listeners: dict[str, list[Callable]] = {}

    def subscribe(self, event_type: str, callback: Callable) -> None:
        """Register a callback for an event type."""
        self._listeners.setdefault(event_type, []).append(callback)

    def unsubscribe(self, event_type: str, callback: Callable) -> None:
        """Remove a callback for an event type."""
        if event_type in self._listeners:
            self._listeners[event_type] = [
                cb for cb in self._listeners[event_type] if cb is not callback
            ]

    def publish(self, event_type: str, data: Any) -> None:
        """Publish data to all subscribers of an event type."""
        for callback in self._listeners.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    # Check for a running loop; if none, sync callers must await
                    try:
                        loop = asyncio.get_running_loop()
                        task = loop.create_task(callback(data))
                        task.add_done_callback(
                            lambda t: None if t.exception() is None else t.exception()
                        )
                    except RuntimeError:
                        # No running loop — schedule for the next one
                        asyncio.ensure_future(callback(data))
                else:
                    callback(data)
            except Exception:
                pass  # Don't let one bad subscriber break the bus

    def clear(self, event_type: Optional[str] = None) -> None:
        """Clear all listeners, or just for a specific event type."""
        if event_type is None:
            self._listeners.clear()
        elif event_type in self._listeners:
            del self._listeners[event_type]
