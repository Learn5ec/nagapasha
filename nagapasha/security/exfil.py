"""Host allowlist for exfiltration prevention.

Prevents test requests from being sent to unauthorized external hosts.
When enabled, only requests matching the allowlist (derived from the
target's base URL) are allowed to proceed. This prevents accidental
data exfiltration to attacker-controlled domains during testing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class ExfilEvent:
    """Record of a blocked exfiltration attempt."""

    original_url: str
    blocked_url: str
    reason: str
    timestamp: float = 0.0

    def to_dict(self) -> dict:
        return {
            "original_url": self.original_url,
            "blocked_url": self.blocked_url,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


class HostAllowlist:
    """Validates URLs against a set of allowed hosts/domains.

    Usage:
        allowlist = HostAllowlist(
            allowed=["example.com", "api.example.com"],
            allow_subdomains=True,
        )
        if allowlist.is_allowed("https://example.com/api/users"):
            # safe to send request
        else:
            # blocked — exfiltration attempt
    """

    # Characters that should not appear in legitimate URLs
    _suspicious_chars = re.compile(r"[\\;\'\"\`]|\\x[0-9a-fA-F]{2}")

    def __init__(
        self,
        allowed: Optional[list[str]] = None,
        allow_subdomains: bool = True,
        allow_localhost: bool = False,
        allow_ip_ranges: Optional[list[str]] = None,
    ) -> None:
        self.allowed = set(allowed or [])
        self.allow_subdomains = allow_subdomains
        self.allow_localhost = allow_localhost
        self.allow_ip_ranges = allow_ip_ranges or []
        self._blocked: list[ExfilEvent] = []

    def is_allowed(self, url: str) -> bool:
        """Check if a URL is allowed by the allowlist.

        Args:
            url: The URL to check.

        Returns:
            True if the URL matches an allowed host, False otherwise.
        """
        if not url:
            return False

        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Check for suspicious characters in hostname only (not full URL)
        if self._suspicious_chars.search(hostname):
            self._record_blocked(url, url, "suspicious_characters")
            return False

        # Check localhost
        if hostname in ("localhost", "127.0.0.1", "::1") and self.allow_localhost:
            return True

        # Check IP ranges
        for ip_range in self.allow_ip_ranges:
            if self._matches_ip_range(hostname, ip_range):
                return True

        # Check allowed hosts
        for allowed_host in self.allowed:
            if hostname == allowed_host:
                return True
            if self.allow_subdomains and hostname.endswith(f".{allowed_host}"):
                return True

        # Blocked
        self._record_blocked(url, url, "host_not_in_allowlist")
        return False

    def _record_blocked(self, original_url: str, blocked_url: str, reason: str) -> None:
        """Record a blocked exfiltration attempt."""
        import time
        self._blocked.append(ExfilEvent(
            original_url=original_url,
            blocked_url=blocked_url,
            reason=reason,
            timestamp=time.time(),
        ))
        logger.warning(f"Exfiltration blocked: {blocked_url} — {reason}")

    def get_blocked_events(self) -> list[ExfilEvent]:
        """Return list of blocked exfiltration events."""
        return list(self._blocked)

    def add_allowed(self, host: str) -> None:
        """Add a host to the allowlist."""
        self.allowed.add(host)

    def remove_allowed(self, host: str) -> None:
        """Remove a host from the allowlist."""
        self.allowed.discard(host)

    def clear_blocked(self) -> None:
        """Clear blocked events log."""
        self._blocked.clear()

    @staticmethod
    def _matches_ip_range(hostname: str, ip_range: str) -> bool:
        """Simple CIDR matching for IPv4.

        Args:
            hostname: The hostname to check.
            ip_range: CIDR notation (e.g. "192.168.1.0/24").

        Returns:
            True if the hostname matches the IP range.
        """
        try:
            if "/" not in ip_range:
                return hostname == ip_range
            ip, prefix = ip_range.split("/")
            prefix_len = int(prefix)

            # Convert IPs to integers
            ip_parts = ip.split(".")
            if len(ip_parts) != 4:
                return False
            ip_int = (
                (int(ip_parts[0]) << 24)
                | (int(ip_parts[1]) << 16)
                | (int(ip_parts[2]) << 8)
                | int(ip_parts[3])
            )

            hostname_parts = hostname.split(".")
            if len(hostname_parts) != 4:
                return False
            host_int = (
                (int(hostname_parts[0]) << 24)
                | (int(hostname_parts[1]) << 16)
                | (int(hostname_parts[2]) << 8)
                | int(hostname_parts[3])
            )

            mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
            return (ip_int & mask) == (host_int & mask)
        except (ValueError, IndexError):
            return False
