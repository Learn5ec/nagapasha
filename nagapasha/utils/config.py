"""Configuration utilities for nagapasha.

Loads configuration from environment variables and config files.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

# Global config cache
_config_cache: Optional[dict[str, Any]] = None


def get_config() -> dict[str, Any]:
    """Get the application configuration.

    Loads from environment variables first, then from config file if available.

    Returns:
        Configuration dictionary
    """
    global _config_cache

    if _config_cache is not None:
        return _config_cache

    # Load from environment
    config = {
        # Engagement HMAC key (required for signing)
        "engagement_hmac_key": os.environ.get("NAGAPASHA_HMAC_KEY", ""),

        # LLM configuration
        "anthropic_api_key": os.environ.get("ANTHROPIC_API_KEY", ""),
        "anthropic_base_url": os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),

        # MCP configuration
        "mcp_search_enabled": os.environ.get("MCP_SEARCH_ENABLED", "false").lower() == "true",
        "brave_api_key": os.environ.get("BRAVE_API_KEY", ""),

        # Temp directory
        "temp_dir": os.environ.get("NAGAPASHA_TEMP_DIR", "/tmp/nagapasha"),

        # Rate limiting
        "hard_rate_ceiling": int(os.environ.get("NAGAPASHA_HARD_RATE_CEILING", "10")),

        # Logging
        "log_level": os.environ.get("NAGAPASHA_LOG_LEVEL", "INFO"),
        "log_json": os.environ.get("NAGAPASHA_LOG_JSON", "false").lower() == "true",
    }

    # Try to load from config file
    config_path = Path.home() / ".nagapasha" / "config.yaml"
    if config_path.exists():
        try:
            import yaml
            file_config = yaml.safe_load(config_path.read_text()) or {}
            config.update(file_config)
        except Exception:
            pass  # Ignore config file errors

    _config_cache = config
    return config


def reset_config() -> None:
    """Reset config cache (useful for testing)."""
    global _config_cache
    _config_cache = None
