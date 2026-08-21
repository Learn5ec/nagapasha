"""Tests for the Librarian agent (Stage 7)."""

from pathlib import Path

import pytest
import pytest_asyncio

from nagapasha.stages.stage07_librarian import (
    get_default_payloads,
    run_librarian,
)


class TestGetDefaultPayloads:
    def test_contains_common_attacks(self):
        """Default payloads should include common attack classes."""
        payloads = get_default_payloads()
        assert "sql_injection" in payloads
        assert "xss" in payloads
        assert "lfi" in payloads

    def test_payloads_have_required_fields(self):
        """Each payload should have value, encoding, and technique."""
        payloads = get_default_payloads()
        for attack_class, payload_list in payloads.items():
            assert isinstance(payload_list, list)
            for p in payload_list:
                assert "value" in p
                assert "encoding" in p
                assert "technique" in p

    def test_sqli_payloads(self):
        """SQLi payloads should include common patterns."""
        payloads = get_default_payloads()
        sqli = payloads["sql_injection"]
        values = [p["value"] for p in sqli]
        assert any("' OR '1'='1" in v for v in values)

    def test_xss_payloads(self):
        """XSS payloads should include reflected XSS."""
        payloads = get_default_payloads()
        xss = payloads["xss"]
        values = [p["value"] for p in xss]
        assert any("<script>alert(1)</script>" in v for v in values)


class TestRunLibrarian:
    @pytest.mark.asyncio
    async def test_returns_payloads_for_known_attacks(self):
        """Should return default payloads for known attack classes when no KB."""
        # Without a KB directory, falls back to default payloads
        import nagapasha.stages.stage07_librarian as lib
        lib.KB_DIR = Path("/nonexistent/kb")
        result = await run_librarian(["sql_injection", "xss"])
        assert "sql_injection" in result
        assert "xss" in result

    @pytest.mark.asyncio
    async def test_empty_attack_classes(self):
        """Empty attack class list should return empty dict."""
        result = await run_librarian([])
        assert result == {}
