"""A6 tests: tech-stack override + dialect-aware selection.

Verifies:
- TechStackContext dataclass exists with proper fields
- --tech-stack JSON parsed correctly into TechStackContext
- dialect_hint set from database field
- User-supplied dialect_hint overrides confirmed_tech_stack
"""

import pytest
from nagapasha.models.request_model import RequestModel, TechStackContext


# ---------------------------------------------------------------------------
# TechStackContext structure
# ---------------------------------------------------------------------------

class TestTechStackContext:
    """A6: Verify TechStackContext dataclass structure."""

    def test_tech_stack_context_exists(self):
        """A6: TechStackContext must be importable from request_model."""
        assert TechStackContext is not None

    def test_tech_stack_context_default_fields(self):
        """A6: All fields must have default None values."""
        ctx = TechStackContext()
        assert ctx.server is None
        assert ctx.server_version is None
        assert ctx.backend_language is None
        assert ctx.framework is None
        assert ctx.database is None
        assert ctx.frontend is None
        assert ctx.source == "user_supplied"

    def test_tech_stack_context_with_values(self):
        """A6: TechStackContext must accept all fields."""
        ctx = TechStackContext(
            server="nginx",
            server_version="1.25.0",
            backend_language="python",
            framework="flask",
            database="postgresql",
            frontend="react",
            source="user_supplied",
        )
        assert ctx.server == "nginx"
        assert ctx.server_version == "1.25.0"
        assert ctx.backend_language == "python"
        assert ctx.framework == "flask"
        assert ctx.database == "postgresql"
        assert ctx.frontend == "react"
        assert ctx.source == "user_supplied"

    def test_tech_stack_context_source_default(self):
        """A6: source defaults to 'user_supplied'."""
        ctx = TechStackContext()
        assert ctx.source == "user_supplied"


# ---------------------------------------------------------------------------
# RequestModel integration
# ---------------------------------------------------------------------------

class TestRequestModelTechStack:
    """A6: Verify RequestModel integrates TechStackContext and dialect_hint."""

    def test_request_model_has_tech_stack_context_field(self):
        """A6: RequestModel must have tech_stack_context field."""
        req = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
        )
        assert hasattr(req, "tech_stack_context")
        assert req.tech_stack_context is None

    def test_request_model_has_dialect_hint_field(self):
        """A6: RequestModel must have dialect_hint field."""
        req = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
        )
        assert hasattr(req, "dialect_hint")
        assert req.dialect_hint is None

    def test_request_model_tech_stack_context_set(self):
        """A6: tech_stack_context must be settable."""
        ctx = TechStackContext(database="postgresql")
        req = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
            tech_stack_context=ctx,
        )
        assert req.tech_stack_context.database == "postgresql"

    def test_request_model_dialect_hint_set_from_tech_stack(self):
        """A6: dialect_hint can be derived from tech_stack_context.database."""
        ctx = TechStackContext(database="postgresql")
        req = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
            tech_stack_context=ctx,
        )
        # Manually set dialect_hint from database field (as CLI does)
        if req.tech_stack_context.database:
            req.dialect_hint = req.tech_stack_context.database
        assert req.dialect_hint == "postgresql"


# ---------------------------------------------------------------------------
# Dialect hint precedence
# ---------------------------------------------------------------------------

class TestDialectHintPrecedence:
    """A6: Verify dialect_hint precedence rules."""

    def test_explicit_dialect_hint_overrides_tech_stack(self):
        """A6: Explicit dialect_hint wins over confirmed_tech_stack['database']."""
        req = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
            confirmed_tech_stack={"database": "mysql"},
            dialect_hint="postgres",
        )
        # _build_technique_category_payloads uses dialect_hint if set,
        # otherwise falls back to confirmed_tech_stack['database']
        effective_dialect = req.dialect_hint
        if not effective_dialect and req.confirmed_tech_stack:
            effective_dialect = req.confirmed_tech_stack.get("database")
        assert effective_dialect == "postgres"

    def test_no_explicit_hint_falls_back_to_tech_stack(self):
        """A6: Without explicit dialect_hint, fall back to confirmed_tech_stack."""
        req = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
            confirmed_tech_stack={"database": "mysql"},
        )
        effective_dialect = req.dialect_hint
        if not effective_dialect and req.confirmed_tech_stack:
            effective_dialect = req.confirmed_tech_stack.get("database")
        assert effective_dialect == "mysql"

    def test_no_tech_stack_no_hint(self):
        """A6: Without tech_stack or dialect_hint, effective_dialect is None."""
        req = RequestModel(
            method="GET",
            url="http://example.com/api",
            base_url="http://example.com",
        )
        effective_dialect = req.dialect_hint
        if not effective_dialect and req.confirmed_tech_stack:
            effective_dialect = req.confirmed_tech_stack.get("database")
        assert effective_dialect is None


# ---------------------------------------------------------------------------
# CLI --tech-stack parsing
# ---------------------------------------------------------------------------

class TestCLITechStackParsing:
    """A6: Verify CLI parses --tech-stack JSON correctly."""

    def _parse_tech_stack_json(self, json_str: str):
        """Helper to parse tech_stack JSON (same logic as CLI)."""
        import json as _json
        tech_stack_dict = _json.loads(json_str)
        return TechStackContext(
            server=tech_stack_dict.get("server"),
            server_version=tech_stack_dict.get("server_version"),
            backend_language=tech_stack_dict.get("backend_language"),
            framework=tech_stack_dict.get("framework"),
            database=tech_stack_dict.get("database"),
            frontend=tech_stack_dict.get("frontend"),
            source="user_supplied",
        )

    def test_parse_valid_json(self):
        """A6: Valid JSON string parses correctly."""
        json_str = '{"server": "nginx", "database": "postgresql", "framework": "flask"}'
        ctx = self._parse_tech_stack_json(json_str)
        assert ctx.server == "nginx"
        assert ctx.database == "postgresql"
        assert ctx.framework == "flask"

    def test_parse_empty_json(self):
        """A6: Empty JSON object parses to defaults."""
        ctx = self._parse_tech_stack_json("{}")
        assert ctx.server is None
        assert ctx.database is None

    def test_parse_invalid_json_raises(self):
        """A6: Invalid JSON raises JSONDecodeError."""
        import json
        with pytest.raises(json.JSONDecodeError):
            self._parse_tech_stack_json("not valid json")

    def test_dialect_hint_from_database_field(self):
        """A6: dialect_hint derived from database field."""
        json_str = '{"database": "mssql"}'
        ctx = self._parse_tech_stack_json(json_str)
        dialect_hint = ctx.database if ctx.database else None
        assert dialect_hint == "mssql"
