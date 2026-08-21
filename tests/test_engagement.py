"""Tests for EngagementContext model (Stage 0)."""

import json
from datetime import datetime, timezone

import pytest

from nagapasha.engagement import (
    EngagementContext,
    hash_roe,
    validate_roe,
    write_kill_switch,
    read_kill_switch,
)


class TestEngagementContext:
    def test_create_basic(self):
        """Test basic engagement context creation."""
        context = EngagementContext.create(
            engagement_id="test-123",
            roe_hash="sha256:test",
            scope_allowlist=["example.com"],
            scope_denylist=["cdn.example.com"],
            allowed_methods=["GET", "POST"],
            allowed_attack_classes=[],
            time_window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            time_window_end=datetime(2026, 12, 31, tzinfo=timezone.utc),
            authorized_by="test@example.com",
        )

        assert context.engagement_id == "test-123"
        assert context.roe_hash == "sha256:test"
        assert "example.com" in context.scope_allowlist
        assert "cdn.example.com" in context.scope_denylist

    def test_to_dict_serialization(self):
        """Test dict serialization handles datetimes."""
        context = EngagementContext.create(
            engagement_id="test-123",
            roe_hash="sha256:test",
            scope_allowlist=[],
            scope_denylist=[],
            allowed_methods=["GET"],
            allowed_attack_classes=[],
            time_window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            time_window_end=datetime(2026, 12, 31, tzinfo=timezone.utc),
            authorized_by="test",
        )

        d = context.to_dict()
        assert isinstance(d["created_at"], str)
        assert "2026-01-01" in d["time_window_start"]

    def test_to_json_from_json(self):
        """Test JSON round-trip serialization."""
        context = EngagementContext.create(
            engagement_id="test-123",
            roe_hash="sha256:test",
            scope_allowlist=["example.com"],
            scope_denylist=[],
            allowed_methods=["GET", "POST"],
            allowed_attack_classes=[],
            time_window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            time_window_end=datetime(2026, 12, 31, tzinfo=timezone.utc),
            authorized_by="test",
        )

        json_str = context.to_json()
        loaded = EngagementContext.from_json(json_str)

        assert loaded.engagement_id == context.engagement_id
        assert loaded.scope_allowlist == context.scope_allowlist

    def test_is_in_scope_allowlist(self):
        """Test scope checking with allowlist."""
        context = EngagementContext.create(
            engagement_id="test",
            roe_hash="sha256:test",
            scope_allowlist=["example.com", "*.example.com"],
            scope_denylist=[],
            allowed_methods=["GET"],
            allowed_attack_classes=[],
            time_window_start=datetime.now(timezone.utc),
            time_window_end=datetime.now(timezone.utc),
            authorized_by="test",
        )

        assert context.is_in_scope("https://example.com/api")
        assert context.is_in_scope("https://api.example.com/test")
        assert not context.is_in_scope("https://evil.com/api")

    def test_is_in_scope_denylist_wins(self):
        """Test that denylist wins over allowlist."""
        context = EngagementContext.create(
            engagement_id="test",
            roe_hash="sha256:test",
            scope_allowlist=["*.example.com"],
            scope_denylist=["cdn.example.com"],
            allowed_methods=["GET"],
            allowed_attack_classes=[],
            time_window_start=datetime.now(timezone.utc),
            time_window_end=datetime.now(timezone.utc),
            authorized_by="test",
        )

        assert context.is_in_scope("https://cdn.example.com/api") == False
        assert context.is_in_scope("https://www.example.com/api")

    def test_is_method_allowed(self):
        """Test method allowlist checking."""
        context = EngagementContext.create(
            engagement_id="test",
            roe_hash="sha256:test",
            scope_allowlist=[],
            scope_denylist=[],
            allowed_methods=["GET", "POST"],
            allowed_attack_classes=[],
            time_window_start=datetime.now(timezone.utc),
            time_window_end=datetime.now(timezone.utc),
            authorized_by="test",
        )

        assert context.is_method_allowed("GET")
        assert context.is_method_allowed("POST")
        assert not context.is_method_allowed("DELETE")

    def test_is_attack_class_allowed(self):
        """Test attack class allowlist checking."""
        context = EngagementContext.create(
            engagement_id="test",
            roe_hash="sha256:test",
            scope_allowlist=[],
            scope_denylist=[],
            allowed_methods=["GET"],
            allowed_attack_classes=["sql_injection", "xss"],
            time_window_start=datetime.now(timezone.utc),
            time_window_end=datetime.now(timezone.utc),
            authorized_by="test",
        )

        assert context.is_attack_class_allowed("sql_injection")
        assert context.is_attack_class_allowed("xss")
        assert not context.is_attack_class_allowed("rce")

    def test_is_time_window_valid(self):
        """Test time window validation."""
        # Valid time window
        context = EngagementContext.create(
            engagement_id="test",
            roe_hash="sha256:test",
            scope_allowlist=[],
            scope_denylist=[],
            allowed_methods=["GET"],
            allowed_attack_classes=[],
            time_window_start=datetime(2020, 1, 1, tzinfo=timezone.utc),
            time_window_end=datetime(2030, 12, 31, tzinfo=timezone.utc),
            authorized_by="test",
        )
        assert context.is_time_window_valid()

        # Expired time window
        context_expired = EngagementContext.create(
            engagement_id="test",
            roe_hash="sha256:test",
            scope_allowlist=[],
            scope_denylist=[],
            allowed_methods=["GET"],
            allowed_attack_classes=[],
            time_window_start=datetime(2020, 1, 1, tzinfo=timezone.utc),
            time_window_end=datetime(2021, 1, 1, tzinfo=timezone.utc),
            authorized_by="test",
        )
        assert not context_expired.is_time_window_valid()


class TestHashRoe:
    def test_hash_roe(self):
        """Test ROE hashing."""
        roe_content = "target_hosts:\n  - example.com"
        h = hash_roe(roe_content)
        assert len(h) == 64  # SHA256 hex digest length
        assert h == hash_roe(roe_content)  # Deterministic


class TestValidateRoe:
    def test_validate_roe_basic(self):
        """Test basic ROE validation."""
        roe_data = {
            "target_hosts": ["example.com"],
            "allowed_methods": ["GET", "POST"],
            "authorized_by": "test@example.com",
        }

        context = validate_roe(roe_data, "test-engagement")
        assert context.engagement_id == "test-engagement"
        assert "example.com" in context.scope_allowlist

    def test_validate_roe_missing_fields(self):
        """Test ROE validation fails on missing required fields."""
        roe_data = {
            "authorized_by": "test@example.com",
        }

        with pytest.raises(ValueError, match="Missing required ROE field"):
            validate_roe(roe_data, "test-engagement")


class TestKillSwitch:
    def test_write_read_kill_switch(self, tmp_path):
        """Test kill switch write and read."""
        import os
        os.chdir(tmp_path)

        write_kill_switch("test-engagement")
        assert read_kill_switch("test-engagement") == True

        # Clean up
        import shutil
        shutil.rmtree(tmp_path / "test-engagement.state")
