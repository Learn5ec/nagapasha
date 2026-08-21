"""Scope guard — authorization and kill switch.

Enforces:
- Explicit scope confirmation before the first live request
- Hard cap on total request volume per run
- Clean kill switch on Ctrl-C
"""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScopeGuard:
    """Manages authorization, request limits, and kill switching."""

    # Configuration
    max_requests: int = 10000       # hard cap per run
    scope_confirmation: bool = False
    confirmation_message: str = ""  # timestamped confirmation

    # Runtime state
    request_count: int = 0
    _kill_requested: bool = False
    _kill_event: Optional[asyncio.Event] = None

    @property
    def kill_event(self) -> asyncio.Event:
        if self._kill_event is None:
            self._kill_event = asyncio.Event()
        return self._kill_event

    def confirm_scope(self, message: str) -> bool:
        """Record explicit scope confirmation.

        Returns True if confirmation was successfully recorded.
        """
        if not message.strip():
            return False
        self.scope_confirmation = True
        self.confirmation_message = message
        return True

    def check_scope(self) -> bool:
        """Check if scope has been confirmed."""
        return self.scope_confirmation

    def check_and_increment(self) -> bool:
        """Check scope, request limit, and kill switch.

        Returns True if the request should proceed.
        """
        if not self.scope_confirmation:
            return False

        if self.request_count >= self.max_requests:
            return False

        if self._kill_requested:
            return False

        self.request_count += 1
        return True

    def request_kill(self) -> None:
        """Signal that a kill is requested (e.g. Ctrl-C)."""
        self._kill_requested = True
        if self._kill_event:
            self._kill_event.set()

    async def wait_for_kill(self) -> None:
        """Block until kill is signaled."""
        if self._kill_event:
            await self._kill_event.wait()

    def is_killed(self) -> bool:
        """Check if kill has been requested."""
        return self._kill_requested

    def reset(self) -> None:
        """Reset all state (for testing or reruns)."""
        self.scope_confirmation = False
        self.confirmation_message = ""
        self.request_count = 0
        self._kill_requested = False
        self._kill_event = None
