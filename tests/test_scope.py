"""Tests for ScopeChecker (Stage 0)."""

from datetime import datetime, timezone

import pytest

from nagapasha.engagement import EngagementContext
from nagapasha.scope import ScopeChecker, ScopeError, enforce_scope


def _make_context(**overrides):
    """Helper to create a basic engagement context."""
    defaults = {
        "engagement_id": "test",
        "roe_hash": "sha256:test",
        "scope_allowlist": ["example.com"],
        "scope_denylist": [],
        "allowed_methods": ["GET", "POST"],
        "allowed_attack_classes": [],
        "time_window_start": datetime(2020, 1, 1, tzinfo=timezone.utc),
        "time_window_end": datetime(2030, 12, 31, tzinfo=timezone.utc),
        "authorized_by": "test@example.com",
    }
    defaults.update(overrides)
    return EngagementContext.create(**defaults)


class TestScopeChecker:
    def test_check_in_scope(self):
        """Test scope check passes for in-scope request."""
        context = _make_context(scope_allowlist=["example.com"])
        checker = ScopeChecker(context)
        checker.check(url="https://example.com/api", method="GET")

    def test_check_out_of_scope(self):
        """Test scope check fails for out-of-scope request."""
        context = _make_context(scope_allowlist=["example.com"])
        checker = ScopeChecker(context)

        with pytest.raises(ScopeError, match="out of scope"):
            checker.check(url="https://evil.com/api", method="GET")

    def test_check_method_not_allowed(self):
        """Test scope check fails for disallowed method."""
        context = _make_context(allowed_methods=["GET"])
        checker = ScopeChecker(context)

        with pytest.raises(ScopeError, match="not allowed"):
            checker.check(url="https://example.com/api", method="DELETE")

    def test_check_attack_class_not_allowed(self):
        """Test scope check fails for disallowed attack class."""
        context = _make_context(
            allowed_attack_classes=["sql_injection", "xss"]
        )
        checker = ScopeChecker(context)

        with pytest.raises(ScopeError, match="not allowed"):
            checker.check(
                url="https://example.com/api",
                method="GET",
                attack_class="rce",
            )

    def test_check_denylist_wins(self):
        """Test that denylist overrides allowlist."""
        context = _make_context(
            scope_allowlist=["example.com"],
            scope_denylist=["cdn.example.com"],
        )
        checker = ScopeChecker(context)

        with pytest.raises(ScopeError, match="out of scope"):
            checker.check(url="https://cdn.example.com/api", method="GET")

    def test_check_kill_switch(self, tmp_path):
        """Test scope check fails when kill switch is active."""
        import os
        import shutil
        original_cwd = os.getcwd()
        os.chdir(tmp_path)

        try:
            context = _make_context()
            checker = ScopeChecker(context)

            # Write kill switch
            from nagapasha.engagement import write_kill_switch
            write_kill_switch("test")

            with pytest.raises(ScopeError, match="Kill switch"):
                checker.check(url="https://example.com/api", method="GET")
        finally:
            # Cleanup
            os.chdir(original_cwd)
            shutil.rmtree(tmp_path, ignore_errors=True)

    def test_check_time_window_expired(self):
        """Test scope check fails when time window expired."""
        context = _make_context(
            time_window_start=datetime(2020, 1, 1, tzinfo=timezone.utc),
            time_window_end=datetime(2021, 1, 1, tzinfo=timezone.utc),
        )
        checker = ScopeChecker(context)

        with pytest.raises(ScopeError, match="time window"):
            checker.check(url="https://example.com/api", method="GET")

    def test_check_url_only(self):
        """Test URL-only scope check."""
        context = _make_context(scope_allowlist=["example.com"])
        checker = ScopeChecker(context)

        # Should not raise
        checker.check_url(url="https://example.com/api", description="test")

        with pytest.raises(ScopeError, match="out of scope"):
            checker.check_url(url="https://evil.com/api", description="test")


class TestEnforceScope:
    def test_enforce_scope_convenience(self):
        """Test enforce_scope convenience function."""
        context = _make_context()

        # Should not raise
        enforce_scope(context, "https://example.com/api", "GET")

        # Should raise
        with pytest.raises(ScopeError):
            enforce_scope(context, "https://evil.com/api", "GET")
