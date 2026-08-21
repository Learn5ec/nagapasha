"""Notification utilities.

Sends OS-native notifications and optionally Slack webhooks.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Optional


def send_notification(title: str, message: str) -> bool:
    """Send an OS-native notification.

    Uses osascript on macOS, notify-send on Linux, and prints on Windows.
    Returns True if notification was sent successfully.
    """
    import platform
    os_name = platform.system()

    try:
        if os_name == "Darwin":
            # macOS
            script = f'display notification "{message}" with title "{title}"'
            subprocess.run(["osascript", "-e", script],
                           capture_output=True, timeout=5)
            return True

        elif os_name == "Linux":
            # Linux (GNOME, KDE, etc.)
            subprocess.run(
                ["notify-send", title, message],
                capture_output=True, timeout=5,
            )
            return True

        else:
            # Windows / unknown — just print
            print(f"\n[NOTIFICATION] {title}: {message}")
            return True

    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        # Fallback: just print
        print(f"\n[NOTIFICATION] {title}: {message}")
        return True


def send_slack_webhook(
    webhook_url: str,
    text: str,
    channel: Optional[str] = None,
) -> bool:
    """Send a notification to a Slack webhook.

    Returns True if the notification was sent successfully.
    """
    try:
        import urllib.request
        import json

        payload = {"text": text}
        if channel:
            payload["channel"] = channel

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200

    except Exception:
        return False


def notify_run_complete(title: str, message: str) -> None:
    """Notify that a run has completed."""
    send_notification(title, message)
    # Also print to console for visibility
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"  {message}")
    print(f"{'='*60}\n")
