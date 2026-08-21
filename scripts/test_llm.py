#!/usr/bin/env python3
"""Test LLM connectivity and basic API call.

Usage:
    python scripts/test_llm.py
    python scripts/test_llm.py --model claude-opus-4-20250514
    python scripts/test_llm.py --dry-run  # Test without sending request
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Load .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


async def test_llm_connectivity(model: str = None, dry_run: bool = False):
    """Test LLM connectivity with a simple prompt."""
    from nagapasha.llm.runner import (
        AnthropicRunner,
        ANTHROPIC_BASE_URL,
        ANTHROPIC_MODEL,
        LLM_TIMEOUT,
    )

    target_model = model or ANTHROPIC_MODEL
    print(f"Testing LLM connectivity...")
    print(f"  Base URL: {ANTHROPIC_BASE_URL}")
    print(f"  Model: {target_model}")
    print(f"  Timeout: {LLM_TIMEOUT}s")

    if dry_run:
        print("\n[Dry run] Would send prompt to Anthropic API")
        print(f"  Model: {target_model}")
        return True

    # Test with a simple prompt that should return plain text
    prompt = "Say 'LLM connectivity test successful' in exactly 5 words."

    runner = AnthropicRunner(model=target_model, timeout=30)
    try:
        print(f"\nSending prompt: {prompt!r}")
        result = await runner.invoke(
            stage="test",
            context={"prompt": prompt},
        )
        # Handle both JSON and plain text responses
        if isinstance(result, dict):
            data = result.get("data", {})
            if isinstance(data, dict):
                print(f"  Error field: {data.get('error', 'N/A')}")
            else:
                print(f"  Response: {data}")
        else:
            print(f"  Response: {result}")
        print("\n✓ LLM connectivity test PASSED")
        return True
    except Exception as e:
        print(f"\n✗ LLM connectivity test FAILED")
        print(f"  Error: {e}")
        return False
    finally:
        await runner.close()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Test LLM connectivity")
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Claude model to use (default: from .env or claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be sent without actually calling the API",
    )
    args = parser.parse_args()

    # Check if ANTHROPIC_AUTH_TOKEN is set
    if not os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        print("ERROR: ANTHROPIC_AUTH_TOKEN not set in .env or environment")
        print("Please set it in .env or export it before running this script")
        sys.exit(1)

    success = asyncio.run(test_llm_connectivity(model=args.model, dry_run=args.dry_run))
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
