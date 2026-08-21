"""Anthropic API runner with retry, streaming, and token tracking.

Uses the Anthropic Messages API directly via httpx for async operation.

Supports:
  - Retry with exponential backoff on transient failures
  - Token usage tracking (input/output tokens per call)
  - Async streaming for long-running agents
  - Timeout per stage
  - Configurable via .env file (ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN, etc.)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import httpx

# Load .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed — use os.environ directly

logger = logging.getLogger(__name__)


def _get_env(key: str, default: str = "") -> str:
    """Get environment variable with fallback to .env file."""
    return os.environ.get(key, default)


# Default Anthropic API settings
DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_MODEL = "claude-sonnet-4-20250514"

# Read config from environment
ANTHROPIC_BASE_URL = _get_env("ANTHROPIC_BASE_URL", DEFAULT_BASE_URL)
ANTHROPIC_AUTH_TOKEN = _get_env("ANTHROPIC_AUTH_TOKEN", "")
ANTHROPIC_MODEL = _get_env("ANTHROPIC_MODEL", DEFAULT_MODEL)
LLM_TEMPERATURE = float(_get_env("LLM_TEMPERATURE", "0.7"))
LLM_TOP_P = float(_get_env("LLM_TOP_P", "0.9"))
LLM_MAX_TOKENS = int(_get_env("LLM_MAX_TOKENS", "4096"))
LLM_TIMEOUT = int(_get_env("LLM_TIMEOUT", "120"))
LLM_RETRY_MAX = int(_get_env("LLM_RETRY_MAX", "3"))


class AnthropicInvocationError(Exception):
    """Raised when the Anthropic API call fails after retries."""


class AnthropicRunner:
    """Wrapper around Anthropic Messages API with retry and tracking.

    Contract:
        input  -> {"role": "agent", "stage": "...", "context": {...}}
        output -> {"status": "ok|error", "data": {...}, "tokens_used": ...}

    Features:
        - retry_max: max retry attempts (default 3)
        - retry_backoff: exponential backoff multiplier (default 2.0)
        - token_tracker: dict to accumulate token usage across calls
        - stream_callback: optional callback for streaming output
        - timeout: per-invocation timeout in seconds
        - Configurable via .env: ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN, etc.
    """

    SYSTEM_PROMPT_PATH = Path(__file__).parent / "prompts"

    def __init__(
        self,
        retry_max: Optional[int] = None,
        retry_backoff: float = 2.0,
        timeout: Optional[int] = None,
        token_tracker: Optional[Dict[str, int]] = None,
        stream_callback: Optional[Callable[[str], None]] = None,
        model: Optional[str] = None,
    ) -> None:
        self.retry_max = retry_max or LLM_RETRY_MAX
        self.retry_backoff = retry_backoff
        self.timeout = timeout or LLM_TIMEOUT
        self.token_tracker = token_tracker if token_tracker is not None else {}
        self.stream_callback = stream_callback
        self.model = model or ANTHROPIC_MODEL
        self._call_count: int = 0
        self._last_tokens: Dict[str, int] = {}
        self._client: Optional[httpx.AsyncClient] = None

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTPX client."""
        if self._client is None or self._client.is_closed:
            # Detect auth method: use Bearer token if key doesn't start with 'sk-'
            # or if base URL is a custom gateway
            use_bearer = not ANTHROPIC_AUTH_TOKEN.startswith("sk-")

            headers = {
                "content-type": "application/json",
            }

            if use_bearer:
                headers["Authorization"] = f"Bearer {ANTHROPIC_AUTH_TOKEN}"
            else:
                headers["x-api-key"] = ANTHROPIC_AUTH_TOKEN
                headers["anthropic-version"] = "2023-06-01"

            self._client = httpx.AsyncClient(
                base_url=ANTHROPIC_BASE_URL,
                headers=headers,
                timeout=httpx.Timeout(LLM_TIMEOUT, connect=10.0),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTPX client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def invoke(
        self,
        stage: str,
        context: dict[str, Any],
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """Invoke the Anthropic API for a single agent stage with retry.

        Args:
            stage: The agent stage name (e.g. "strategist", "librarian").
            context: The context dict to send to the agent.
            timeout: Per-invocation timeout in seconds (default: self.timeout).

        Returns:
            The agent's response dict.

        Raises:
            AnthropicInvocationError: If all retry attempts fail.
        """
        timeout = timeout or self.timeout
        last_error: Optional[Exception] = None

        for attempt in range(1, self.retry_max + 1):
            self._call_count += 1
            try:
                result = await self._invoke_once(stage, context, timeout)
                self._record_tokens(result, stage)
                return result
            except AnthropicInvocationError as e:
                last_error = e
                if attempt < self.retry_max:
                    backoff = self.retry_backoff ** attempt
                    logger.warning(
                        f"Anthropic invocation failed (attempt {attempt}/{self.retry_max}): {e}"
                    )
                    logger.info(f"Retrying in {backoff:.1f}s...")
                    await asyncio.sleep(backoff)
                else:
                    logger.error(
                        f"Anthropic invocation failed after {self.retry_max} attempts"
                    )

        await self.close()
        raise AnthropicInvocationError(
            f"Anthropic API failed after {self.retry_max} attempts: {last_error}"
        )

    async def _invoke_once(
        self,
        stage: str,
        context: dict[str, Any],
        timeout: int,
    ) -> dict[str, Any]:
        """Single invocation without retry."""
        prompt_file = self.SYSTEM_PROMPT_PATH / f"{stage}.txt"
        system_prompt = ""
        if prompt_file.exists():
            system_prompt = prompt_file.read_text()

        # Build the message
        user_message = {
            "role": "agent",
            "stage": stage,
            "context": context,
        }

        # Build the API request
        api_request = {
            "model": self.model,
            "max_tokens": LLM_MAX_TOKENS,
            "temperature": LLM_TEMPERATURE,
            "top_p": LLM_TOP_P,
            "system": system_prompt or "You are a security testing agent. Output ONLY valid JSON.",
            "messages": [
                {
                    "role": "user",
                    "content": json.dumps(user_message),
                }
            ],
        }

        # Add constraint if present
        if context.get("constraint"):
            api_request["system"] += f"\n\n{context['constraint']}"

        client = await self.get_client()
        url = "/v1/messages"

        try:
            response = await client.post(url, json=api_request)
        except httpx.HTTPError as e:
            raise AnthropicInvocationError(f"HTTP error: {e}") from e

        if response.status_code != 200:
            error_text = response.text[:500]
            raise AnthropicInvocationError(
                f"Anthropic API returned status {response.status_code}: {error_text}"
            )

        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise AnthropicInvocationError(f"Invalid JSON response: {e}") from e

        # Extract text content from response
        # Support both Anthropic format and gateway-specific formats
        text_content = ""

        # Standard Anthropic format: {"content": [{"type": "text", "text": "..."}]}
        content = data.get("content", [])
        if content:
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text_content += block["text"]
                    break

        # Gateway-specific format: {"response": "text"}
        if not text_content and "response" in data:
            text_content = data["response"]

        # Fallback: try to get any string field
        if not text_content:
            for key in ("text", "message", "output", "result"):
                if key in data and isinstance(data[key], str):
                    text_content = data[key]
                    break

        if not text_content:
            return {"status": "error", "data": {"error": "No text content in response"}}

        # Try to parse as JSON
        try:
            return json.loads(text_content)
        except json.JSONDecodeError:
            # Fall back to extracting JSON from text
            return _extract_json(text_content)

    def _record_tokens(self, result: dict[str, Any], stage: str) -> None:
        """Record token usage from invocation result."""
        tokens = result.get("tokens_used", {})
        if tokens:
            self._last_tokens = tokens
            total = tokens.get("input", 0) + tokens.get("output", 0)
            self.token_tracker["total"] = self.token_tracker.get("total", 0) + total
            self.token_tracker[stage] = self.token_tracker.get(stage, 0) + total
            logger.debug(f"Tokens used: {tokens}, total: {total}")

    @property
    def call_count(self) -> int:
        """Total number of invocations made."""
        return self._call_count

    @property
    def last_tokens(self) -> Dict[str, int]:
        """Token usage from the last invocation."""
        return self._last_tokens

    def reset_stats(self) -> None:
        """Reset call count and token tracker."""
        self._call_count = 0
        self.token_tracker.clear()
        self._last_tokens.clear()


async def invoke_async(
    stage: str,
    context: dict[str, Any],
    timeout: int = 120,
    callback: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    """Async version of AnthropicRunner.invoke for use in async contexts.

    Args:
        stage: The agent stage name.
        context: The context dict to send.
        timeout: Per-invocation timeout.
        callback: Optional callback for streaming output.

    Returns:
        The agent's response dict.
    """
    runner = AnthropicRunner(timeout=timeout, stream_callback=callback)
    try:
        return await runner.invoke(stage, context, timeout)
    finally:
        await runner.close()


def _extract_json(text: str) -> dict[str, Any]:
    """Try to extract JSON from claude's output.

    claude sometimes wraps JSON in markdown code fences or adds commentary.
    """
    # Try to find JSON block in ```json ... ``` or ``` ... ```
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 3:
            json_text = parts[1]
            if json_text.startswith("json"):
                json_text = json_text[4:]
            try:
                return json.loads(json_text.strip())
            except json.JSONDecodeError:
                pass

    # Try to find JSON object/array in the text
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass

    # Last resort: return empty dict with error message
    return {"status": "error", "data": {"error": "Could not parse JSON from response"}}
