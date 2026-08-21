"""Scope checking middleware for engagement enforcement.

This module provides the ScopeChecker class that validates every outbound request
against the engagement context. It enforces:
- Kill switch (file-based)
- Time window
- Method allowlist
- Host scope (allowlist/denylist)
- Attack class restrictions

The ScopeChecker is called before every HTTP request to ensure the tool never
operates outside the authorized scope.
"""

from __future__ import annotations

from typing import Optional

from nagapasha.engagement import EngagementContext


class ScopeError(Exception):
    """Raised when a request violates engagement scope."""

    pass


class ScopeChecker:
    """Validates outbound requests against engagement context.

    This middleware ensures that every HTTP request (recon, payload, redirect)
    is checked against the engagement scope before being sent. It enforces
    the authorization gate from Stage 0.

    Usage:
        checker = ScopeChecker(engagement_context)
        checker.check(url="https://example.com/api", method="POST", attack_class="sqli")

    Raises:
        ScopeError: If request is out of scope
    """

    def __init__(self, engagement_context: EngagementContext):
        """Initialize ScopeChecker.

        Args:
            engagement_context: Authorization context for this engagement
        """
        self.context = engagement_context

    def check(
        self,
        url: str,
        method: str,
        attack_class: str = "",
        description: str = "",
    ) -> None:
        """Validate request against engagement scope.

        This is called before every outbound HTTP request. It checks:
        1. Kill switch (file-based)
        2. Time window validity
        3. Method allowlist
        4. Host scope (allowlist/denylist)
        5. Attack class restrictions

        Args:
            url: Request URL
            method: HTTP method (GET, POST, etc.)
            attack_class: Attack class (for classification)
            description: Human-readable description (for error messages)

        Raises:
            ScopeError: If request violates any scope rule
        """
        # 1. Check kill switch (highest priority)
        if self.context.is_kill_switch_active():
            raise ScopeError(
                f"Kill switch is ACTIVE — aborting request: {description or url}"
            )

        # 2. Check time window
        if not self.context.is_time_window_valid():
            raise ScopeError(
                f"Engagement time window expired — "
                f"start: {self.context.time_window_start}, "
                f"end: {self.context.time_window_end} — "
                f"request: {description or url}"
            )

        # 3. Check method allowlist (skip if method is empty)
        if method and not self.context.is_method_allowed(method):
            raise ScopeError(
                f"Method '{method}' not allowed — "
                f"allowed: {self.context.allowed_methods} — "
                f"request: {description or url}"
            )

        # 4. Check host scope
        if url and not self.context.is_in_scope(url):
            raise ScopeError(
                f"URL out of scope — {url} — "
                f"allowlist: {self.context.scope_allowlist}, "
                f"denylist: {self.context.scope_denylist} — "
                f"request: {description or url}"
            )

        # 5. Check attack class (only if specified)
        if attack_class and not self.context.is_attack_class_allowed(attack_class):
            raise ScopeError(
                f"Attack class '{attack_class}' not allowed — "
                f"allowed: {self.context.allowed_attack_classes} — "
                f"request: {description or url}"
            )

    def check_url(self, url: str, description: str = "") -> None:
        """Convenience method to check only URL scope (no method/attack class).

        Args:
            url: URL to check
            description: Human-readable description

        Raises:
            ScopeError: If URL is out of scope
        """
        self.check(url=url, method="", attack_class="", description=description)

    def check_method(self, method: str, description: str = "") -> None:
        """Convenience method to check only method (no URL/attack class).

        Args:
            method: HTTP method to check
            description: Human-readable description

        Raises:
            ScopeError: If method is not allowed
        """
        self.check(url="", method=method, attack_class="", description=description)

    def check_attack_class(
        self, attack_class: str, description: str = ""
    ) -> None:
        """Convenience method to check only attack class (no URL/method).

        Args:
            attack_class: Attack class to check
            description: Human-readable description

        Raises:
            ScopeError: If attack class is not allowed
        """
        self.check(url="", method="", attack_class=attack_class, description=description)

    def __repr__(self) -> str:
        """Debug representation."""
        return (
            f"ScopeChecker(engagement_id={self.context.engagement_id}, "
            f"hosts={len(self.context.scope_allowlist)} allow, "
            f"{len(self.context.scope_denylist)} deny)"
        )


def enforce_scope(
    context: EngagementContext,
    url: str,
    method: str,
    attack_class: str = "",
    description: str = "",
) -> None:
    """Convenience function to enforce scope.

    Args:
        context: Engagement context
        url: Request URL
        method: HTTP method
        attack_class: Attack class
        description: Human-readable description

    Raises:
        ScopeError: If request violates scope
    """
    checker = ScopeChecker(context)
    checker.check(url=url, method=method, attack_class=attack_class, description=description)
