"""Path utilities for nagapasha.

Provides functions for managing engagement state directories and temp files.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional


def get_state_dir(engagement_id: str) -> Path:
    """Get the state directory for an engagement.

    State directories store:
    - Checkpoint files
    - Kill switch file
    - Temp payload downloads (24h TTL)
    - JSONL logs

    Args:
        engagement_id: Engagement identifier

    Returns:
        Path to state directory
    """
    state_root = Path.cwd() / f"{engagement_id}.state"
    state_root.mkdir(parents=True, exist_ok=True)
    return state_root


def get_temp_dir(engagement_id: str) -> Path:
    """Get the temp download directory for an engagement.

    Args:
        engagement_id: Engagement identifier

    Returns:
        Path to temp directory
    """
    temp_dir = get_state_dir(engagement_id) / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir


def get_log_file(engagement_id: str) -> Path:
    """Get the log file path for an engagement.

    Args:
        engagement_id: Engagement identifier

    Returns:
        Path to JSONL log file
    """
    log_file = get_state_dir(engagement_id) / "logs.jsonl"
    return log_file


def get_checkpoint_file(engagement_id: str) -> Path:
    """Get the checkpoint file path for an engagement.

    Args:
        engagement_id: Engagement identifier

    Returns:
        Path to checkpoint file
    """
    checkpoint_file = get_state_dir(engagement_id) / "checkpoint.json"
    return checkpoint_file


def cleanup_engagement_state(engagement_id: str) -> None:
    """Clean up all files for an engagement.

    Args:
        engagement_id: Engagement identifier
    """
    state_dir = Path.cwd() / f"{engagement_id}.state"
    if state_dir.exists():
        shutil.rmtree(state_dir)


def cleanup_temp_files(max_age_hours: int = 24) -> int:
    """Clean up temp files older than max_age_hours.

    Args:
        max_age_hours: Maximum age in hours (default: 24)

    Returns:
        Number of files deleted
    """
    import time

    from nagapasha.utils.config import get_config

    config = get_config()
    temp_dir = Path(config.get("temp_dir", "/tmp/nagapasha"))

    if not temp_dir.exists():
        return 0

    deleted = 0
    cutoff_time = time.time() - (max_age_hours * 3600)

    for file_path in temp_dir.rglob("*"):
        if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
            try:
                file_path.unlink()
                deleted += 1
            except Exception:
                pass

    # Clean up empty directories
    for dir_path in sorted(temp_dir.rglob("*"), reverse=True):
        if dir_path.is_dir():
            try:
                dir_path.rmdir()
            except OSError:
                pass  # Directory not empty

    return deleted
