"""Tests for MCP web search integration in the Librarian agent.

These tests verify the MCP fallback logic without requiring an actual
Brave Search API key or MCP server.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from nagapasha.stages.stage07_librarian import (
    get_default_payloads,
    run_librarian,
    _search_local_kb,
    _search_mcp_online,
)
from nagapasha.llm.runner import AnthropicRunner


class TestSearchLocalKB:
    """Tests for local knowledge base search."""

    def test_empty_kb_directory(self):
        """Should return empty dict when KB directory doesn't exist."""
        result = _search_local_kb(["sql_injection", "xss"])
        assert result == {}

    def test_kb_exact_match(self, tmp_path):
        """Should match attack class by exact filename."""
        kb_dir = tmp_path / "kb"
        kb_dir.mkdir()
        (kb_dir / "sql_injection.json").write_text(
            json.dumps({"payloads": [{"value": "' OR 1=1--", "technique": "test"}]})
        )

        with patch(
            "nagapasha.stages.stage07_librarian.KB_DIR", kb_dir
        ):
            result = _search_local_kb(["sql_injection"])
            assert "sql_injection" in result
            assert len(result["sql_injection"]) == 1

    def test_kb_tag_search(self, tmp_path):
        """Should match by tag when exact filename not found."""
        kb_dir = tmp_path / "kb"
        kb_dir.mkdir()
        (kb_dir / "injection_payloads.json").write_text(
            json.dumps({
                "tags": ["sql_injection"],
                "payloads": [{"value": "' OR 1=1--", "technique": "tagged"}],
            })
        )

        with patch(
            "nagapasha.stages.stage07_librarian.KB_DIR", kb_dir
        ):
            result = _search_local_kb(["sql_injection"])
            assert "sql_injection" in result
            assert len(result["sql_injection"]) == 1

    def test_kb_multiple_tag_matches(self, tmp_path):
        """Should collect payloads from multiple files with same tag."""
        kb_dir = tmp_path / "kb"
        kb_dir.mkdir()
        (kb_dir / "injection1.json").write_text(
            json.dumps({"tags": ["xss"], "payloads": [{"value": "<script>1</script>"}]})
        )
        (kb_dir / "injection2.json").write_text(
            json.dumps({"tags": ["xss"], "payloads": [{"value": "<img onerror=1>"}]})
        )

        with patch(
            "nagapasha.stages.stage07_librarian.KB_DIR", kb_dir
        ):
            result = _search_local_kb(["xss"])
            assert len(result["xss"]) == 2


class TestSearchMCPOnline:
    """Tests for MCP web search fallback."""

    @pytest.mark.asyncio
    async def test_no_runner_returns_none(self):
        """Should return None when no runner provided."""
        result = await _search_mcp_online(None, ["sql_injection"], None, 120)
        assert result is None

    @pytest.mark.asyncio
    async def test_runner_returns_payloads(self):
        """Should return payloads when runner provides valid response."""
        runner = MagicMock(spec=AnthropicRunner)
        runner.invoke = AsyncMock(return_value={
            "status": "ok",
            "data": {
                "sql_injection": [
                    {"value": "' OR 1=1--", "technique": "test", "source": "https://github.com/danielmiessler/SecLists"},
                ]
            },
        })

        result = await _search_mcp_online(runner, ["sql_injection"], None, 120)
        assert "sql_injection" in result
        assert len(result["sql_injection"]) == 1

    @pytest.mark.asyncio
    async def test_drops_payloads_without_source(self):
        """Payloads without a source URL should be dropped by provenance vetting."""
        runner = MagicMock(spec=AnthropicRunner)
        runner.invoke = AsyncMock(return_value={
            "status": "ok",
            "data": {
                "sql_injection": [
                    {"value": "' OR 1=1--", "technique": "test"},
                ]
            },
        })

        result = await _search_mcp_online(runner, ["sql_injection"], None, 120)
        assert result is None or len(result.get("sql_injection", [])) == 0

    @pytest.mark.asyncio
    async def test_drops_payloads_from_unvetted_source(self):
        """Payloads from unvetted sources should be skipped in non-interactive mode."""
        runner = MagicMock(spec=AnthropicRunner)
        runner.invoke = AsyncMock(return_value={
            "status": "ok",
            "data": {
                "sql_injection": [
                    {"value": "' OR 1=1--", "technique": "test", "source": "https://unknown-bad-site.com/payloads"},
                ]
            },
        })

        result = await _search_mcp_online(runner, ["sql_injection"], None, 120)
        assert result is None or len(result.get("sql_injection", [])) == 0

    @pytest.mark.asyncio
    async def test_runner_failure_returns_none(self):
        """Should return None when runner raises exception."""
        runner = MagicMock(spec=AnthropicRunner)
        runner.invoke = AsyncMock(side_effect=Exception("API error"))

        result = await _search_mcp_online(runner, ["sql_injection"], None, 120)
        assert result is None

    @pytest.mark.asyncio
    async def test_runner_error_status_returns_none(self):
        """Should return None when runner returns error status."""
        runner = MagicMock(spec=AnthropicRunner)
        runner.invoke = AsyncMock(return_value={
            "status": "error",
            "data": {"error": "search failed"},
        })

        result = await _search_mcp_online(runner, ["sql_injection"], None, 120)
        assert result is None


class TestRunLibrarianMCP:
    """Integration tests for Librarian with MCP fallback."""

    @pytest.mark.asyncio
    async def test_mcp_fallback_when_kb_empty(self):
        """Should use MCP when local KB is empty and MCP is enabled."""
        import nagapasha.stages.stage07_librarian as lib

        with patch.object(lib, "KB_DIR", Path("/nonexistent/kb")):
            runner = MagicMock(spec=AnthropicRunner)
            # _search_mcp_online uses await runner.invoke() -> AsyncMock
            runner.invoke = AsyncMock(return_value={
                "status": "ok",
                "data": {
                    "sql_injection": [
                        {"value": "' OR 1=1--", "technique": "mcp"},
                    ]
                },
            })

            result = await run_librarian(
                ["sql_injection"],
                runner=runner,
                use_mcp=True,
            )
            assert "sql_injection" in result

    @pytest.mark.asyncio
    async def test_mcp_disabled_uses_defaults(self):
        """Should fall back to defaults when MCP is disabled and KB is empty."""
        import nagapasha.stages.stage07_librarian as lib

        with patch.object(lib, "KB_DIR", Path("/nonexistent/kb")):
            result = await run_librarian(
                ["sql_injection"],
                use_mcp=False,
            )
            assert "sql_injection" in result
            assert len(result["sql_injection"]) > 0

    @pytest.mark.asyncio
    async def test_mcp_failure_falls_back_to_defaults(self):
        """Should fall back to defaults when MCP fails."""
        import nagapasha.stages.stage07_librarian as lib

        with patch.object(lib, "KB_DIR", Path("/nonexistent/kb")):
            runner = MagicMock(spec=AnthropicRunner)
            runner.invoke = AsyncMock(side_effect=Exception("API error"))

            result = await run_librarian(
                ["sql_injection"],
                runner=runner,
                use_mcp=True,
            )
            assert "sql_injection" in result
            # Should have default payloads since MCP failed
            assert len(result["sql_injection"]) > 0


class TestTempDownloadManager:
    """Tests for the temp download manager."""

    def test_temp_dir_creation(self, tmp_path):
        """Temp directory should be created on start."""
        from nagapasha.utils.temp_downloads import TempDownloadManager

        manager = TempDownloadManager()
        # Temp dir is module-level constant, but property should work
        assert manager.temp_dir is not None

    def test_allowed_extensions(self):
        """Allowed extensions should be .txt, .zip, .tar.gz."""
        from nagapasha.utils.temp_downloads import ALLOWED_EXTENSIONS

        assert ".txt" in ALLOWED_EXTENSIONS
        assert ".zip" in ALLOWED_EXTENSIONS
        assert ".tar.gz" in ALLOWED_EXTENSIONS
        assert ".exe" not in ALLOWED_EXTENSIONS

    def test_ttl_config(self):
        """TTL should be 24 hours, cleanup interval 1 hour."""
        from nagapasha.utils.temp_downloads import TTL, CLEANUP_INTERVAL

        assert TTL == 86400  # 24 hours
        assert CLEANUP_INTERVAL == 3600  # 1 hour
