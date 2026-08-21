"""Tests for destructive payload confirmation (Stage 8.5)."""

import os
from unittest.mock import patch

import pytest

from nagapasha.utils.confirm import (
    BENIGN_CLASSES,
    DESTRUCTIVE_CLASSES,
    confirm_destructive,
    is_destructive_class,
    suggest_probe_variant,
)


class TestIsDestructiveClass:
    def test_destructive_classes(self):
        """Test destructive attack class identification."""
        assert is_destructive_class("rce") == True
        assert is_destructive_class("command_injection") == True
        assert is_destructive_class("deserialization") == True
        assert is_destructive_class("xxe_write") == True
        assert is_destructive_class("sqli_write") == True
        assert is_destructive_class("ssrf_write") == True

    def test_benign_classes(self):
        """Test benign attack class identification."""
        assert is_destructive_class("sql_injection") == False
        assert is_destructive_class("xss") == False
        assert is_destructive_class("lfi") == False
        assert is_destructive_class("idor") == False
        assert is_destructive_class("path_traversal") == False

    def test_unknown_classes(self):
        """Test unknown attack classes default to non-destructive."""
        assert is_destructive_class("unknown_attack") == False
        assert is_destructive_class("") == False


class TestConfirmDestructive:
    def test_allow_destructive_flag(self):
        """Test that allow_destructive flag bypasses confirmation."""
        assert confirm_destructive(
            "RCE payload",
            "sleep(5)",
            interactive=False,
            allow_destructive=True,
        ) == True

    def test_env_var_allow(self, monkeypatch):
        """Test that environment variable allows destructive payloads."""
        monkeypatch.setenv("NAGAPASHA_ALLOW_DESTRUCTIVE", "1")

        # Clear cache
        from nagapasha.utils import confirm
        confirm._last_confirm = None

        assert confirm_destructive(
            "RCE payload",
            "sleep(5)",
            interactive=False,
        ) == True

    def test_non_interactive_denied(self, monkeypatch):
        """Test that non-interactive mode denies destructive payloads."""
        # Ensure env var is not set
        monkeypatch.delenv("NAGAPASHA_ALLOW_DESTRUCTIVE", raising=False)

        result = confirm_destructive(
            "RCE payload",
            "sleep(5)",
            interactive=False,
            allow_destructive=False,
        )
        assert result == False

    @patch("nagapasha.utils.confirm._prompt_user")
    def test_interactive_approved(self, mock_prompt):
        """Test interactive mode with user approval."""
        mock_prompt.return_value = True

        result = confirm_destructive(
            "RCE payload",
            "sleep(5)",
            interactive=True,
        )
        assert result == True
        mock_prompt.assert_called_once()

    @patch("nagapasha.utils.confirm._prompt_user")
    def test_interactive_denied(self, mock_prompt):
        """Test interactive mode with user denial."""
        mock_prompt.return_value = False

        result = confirm_destructive(
            "RCE payload",
            "sleep(5)",
            interactive=True,
        )
        assert result == False


class TestSuggestProbeVariant:
    def test_rce_probe(self):
        """Test RCE probe variant suggestion."""
        probe = suggest_probe_variant("rce")
        assert probe == "sleep(5)"

    def test_command_injection_probe(self):
        """Test command injection probe variant suggestion."""
        probe = suggest_probe_variant("command_injection")
        assert probe == "sleep(5)"

    def test_xxe_write_probe(self):
        """Test XXE write probe variant suggestion."""
        probe = suggest_probe_variant("xxe_write")
        assert probe == "file:///etc/passwd"

    def test_sqli_write_probe(self):
        """Test SQLi write probe variant suggestion."""
        probe = suggest_probe_variant("sqli_write")
        assert probe == "SLEEP(5)"

    def test_deserialization_no_probe(self):
        """Test that deserialization has no safe probe."""
        probe = suggest_probe_variant("deserialization")
        assert probe is None
