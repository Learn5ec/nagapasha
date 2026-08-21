"""Dry-run runner for logging requests without sending them.

Used during dry-run mode to log all would-be requests for inspection
without actually sending them to the target.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

from nagapasha.engine.runner import HttpxResponse
from nagapasha.models.request_model import RequestModel

logger = logging.getLogger(__name__)


class DryRunRunner:
    """Simulates HTTP requests without sending them.

    Logs request details for inspection during dry-run mode.
    """

    def __init__(
        self,
        rate_limiter: Optional[Any] = None,
        verify_ssl: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._request_count: int = 0
        self._logged_requests: list[dict[str, Any]] = []

    async def send(self, request_model: RequestModel) -> HttpxResponse:
        """Simulate sending a request (don't actually send).

        Args:
            request_model: The RequestModel describing the request to simulate.

        Returns:
            Mock HttpxResponse with simulated data.
        """
        self._request_count += 1

        # Log the request
        log_entry = {
            "request_count": self._request_count,
            "method": request_model.method,
            "url": request_model.url,
            "headers": dict(request_model.headers),
            "body": request_model.body,
            "timestamp": time.time(),
        }
        self._logged_requests.append(log_entry)

        # Log to console
        logger.info(
            f"[DRY-RUN] #{self._request_count} {request_model.method} {request_model.url}"
        )
        if request_model.body:
            logger.info(f"  Body: {request_model.body[:200]}")

        # Return a mock response (simulated)
        return HttpxResponse(
            status_code=200,
            headers={},
            body="",
            elapsed=0.0,
            url=request_model.url,
        )

    async def send_multiple(
        self, request_model: RequestModel, count: int = 3
    ) -> list[HttpxResponse]:
        """Simulate sending the same request multiple times."""
        responses = []
        for _ in range(count):
            resp = await self.send(request_model)
            responses.append(resp)
            await asyncio.sleep(0.01)  # Minimal delay for simulation
        return responses

    async def close(self) -> None:
        """Release resources (no-op for dry-run)."""
        pass

    def get_logged_requests(self) -> list[dict[str, Any]]:
        """Return list of logged requests."""
        return self._logged_requests

    def clear_log(self) -> None:
        """Clear the request log."""
        self._logged_requests.clear()
