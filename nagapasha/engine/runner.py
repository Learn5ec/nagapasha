"""Async HTTP runner using httpx.

Wraps httpx.AsyncClient with rate-limiting, response capture, and
JSON-serializable response objects.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse, urlencode, parse_qs

import httpx

from nagapasha.engine.rate_limiter import TokenBucketRateLimiter, RateLimitConfig
from nagapasha.models.request_model import RequestModel


@dataclass
class HttpxResponse:
    """JSON-serializable response wrapper."""

    status_code: int
    headers: dict[str, str]
    body: str
    elapsed: float
    url: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "elapsed": self.elapsed,
            "url": self.url,
        }


class HttpRunner:
    """Async HTTP runner with rate-limiting and response capture."""

    def __init__(
        self,
        rate_limiter: Optional[TokenBucketRateLimiter] = None,
        verify_ssl: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._request_count: int = 0
        self._client = httpx.AsyncClient(verify=verify_ssl, timeout=timeout)

    async def send(self, request_model: RequestModel) -> HttpxResponse:
        """Send a request and return a structured response.

        Args:
            request_model: The RequestModel describing the request to send.

        Returns:
            An HttpxResponse with captured status, headers, body, elapsed time.
        """
        if self.rate_limiter:
            await self.rate_limiter.acquire()

        self._request_count += 1

        # Build the full URL
        url = self._build_url(request_model)

        # Build request kwargs (verify is set on AsyncClient constructor, not per-request)
        kwargs = {
            "headers": dict(request_model.headers),
        }

        # Add cookies
        if request_model.cookies:
            kwargs["cookies"] = dict(request_model.cookies)

        # Add body if present
        if request_model.body is not None:
            # Set content-type if not already set
            has_content_type = any(
                k.lower() == "content-type" for k in request_model.headers
            )
            if not has_content_type:
                body_type = request_model.body_type or "application/octet-stream"
                kwargs["headers"]["Content-Type"] = body_type
            kwargs["data"] = request_model.body

        start = time.monotonic()
        resp = await self._client.request(
            method=request_model.method,
            url=url,
            **kwargs,
        )
        elapsed = time.monotonic() - start

        response = HttpxResponse(
            status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items()},
            body=resp.text,
            elapsed=elapsed,
            url=str(resp.url),
        )

        # Feed back to rate limiter
        if self.rate_limiter:
            if 200 <= resp.status_code < 300:
                self.rate_limiter.record_2xx()
            elif resp.status_code == 429:
                self.rate_limiter.record_429()

        return response

    async def send_multiple(
        self, request_model: RequestModel, count: int = 3
    ) -> list[HttpxResponse]:
        """Send the same request multiple times (for baseline calibration)."""
        responses = []
        for _ in range(count):
            resp = await self.send(request_model)
            responses.append(resp)
            await asyncio.sleep(0.1)
        return responses

    async def close(self) -> None:
        """Release resources."""
        await self._client.aclose()

    def _build_url(self, req: RequestModel) -> str:
        """Construct full URL from request model components."""
        url = req.url
        # If URL has no scheme, assume https
        if "://" not in url:
            url = "https://" + url
        return url


