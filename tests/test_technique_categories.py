"""Tests for nagapasha/utils/technique_categories.py

Verifies:
- All expected categories exist (including A2 XSS and A3 HTML-injection)
- time_based_blind contains Postgres-specific pg_sleep variants (A1 fix)
- Tuples carry dialect tags
- AUTH_PRIORITY_CATEGORIES covers auth-endpoint credential fields
- XSS and HTML-injection categories have proper sub-context structure
- Every category produces at least one PayloadCandidate via the real generator (P0-3)
- dialect_agnostic flag is set correctly for categories with non-dialect variant keys
"""

import pytest
from nagapasha.utils.technique_categories import (
    TECHNIQUE_CATEGORIES,
    CATEGORY_TARGET_LOCATIONS,
    AUTH_PRIORITY_CATEGORIES,
)


class TestTechniqueCategoriesStructure:
    """Basic structure tests."""

    def test_time_based_blind_has_pg_sleep_variants(self):
        """A1: pg_sleep must be present in time_based_blind.sql variants."""
        variants = TECHNIQUE_CATEGORIES["time_based_blind"]["variants"]["sql"]
        payloads = [v[0] if isinstance(v, tuple) else v for v in variants]
        assert any("pg_sleep" in p for p in payloads), \
            "time_based_blind.sql must contain at least one pg_sleep payload"

    def test_time_based_blind_sql_variants_are_tuples(self):
        """Each SQL variant must be a (payload_str, dialect_tag) tuple."""
        variants = TECHNIQUE_CATEGORIES["time_based_blind"]["variants"]["sql"]
        for v in variants:
            assert isinstance(v, tuple), f"Expected tuple, got {type(v)}"
            assert len(v) == 2, f"Expected (payload, dialect) tuple, got {v}"
            payload, dialect = v
            assert isinstance(payload, str)
            assert isinstance(dialect, str)
            assert dialect in ("mysql", "mssql", "postgres")

    def test_time_based_blind_postgres_variants(self):
        """A1: verify each dialect-tagged payload exists."""
        variants = TECHNIQUE_CATEGORIES["time_based_blind"]["variants"]["sql"]
        pg_variants = [v[0] for v in variants if isinstance(v, tuple) and v[1] == "postgres"]
        assert len(pg_variants) >= 3, "Need at least 3 pg_sleep variants"

        # Statement-terminated
        assert any("pg_sleep(5)" in p and "SELECT" in p for p in pg_variants)
        # String-context
        assert any("pg_sleep(5)" in p and "||" in p for p in pg_variants)

    def test_time_based_blind_mysql_variants(self):
        """MySQL variants must include SLEEP and BENCHMARK."""
        variants = TECHNIQUE_CATEGORIES["time_based_blind"]["variants"]["sql"]
        mysql_variants = [v[0] for v in variants if isinstance(v, tuple) and v[1] == "mysql"]
        assert any("SLEEP(5)" in p for p in mysql_variants)
        assert any("BENCHMARK" in p for p in mysql_variants)

    def test_time_based_blind_mssql_variants(self):
        """MSSQL variant must include WAITFOR DELAY."""
        variants = TECHNIQUE_CATEGORIES["time_based_blind"]["variants"]["sql"]
        mssql_variants = [v[0] for v in variants if isinstance(v, tuple) and v[1] == "mssql"]
        assert any("WAITFOR" in p for p in mssql_variants)

    def test_boolean_differential_has_true_false(self):
        """boolean_differential.sql must have both true and false conditions."""
        variants = TECHNIQUE_CATEGORIES["boolean_differential"]["variants"]["sql"]
        assert "true" in variants
        assert "false" in variants
        assert len(variants["true"]) >= 2
        assert len(variants["false"]) >= 2

    def test_all_categories_have_variants(self):
        """Every category must have a 'variants' key with at least one dialect."""
        for cat_name, cat in TECHNIQUE_CATEGORIES.items():
            assert "variants" in cat, f"{cat_name} missing 'variants'"
            assert len(cat["variants"]) >= 1, f"{cat_name} has no dialect variants"

    def test_category_target_locations_coverage(self):
        """Every category must be mapped to at least one target location."""
        for cat_name in TECHNIQUE_CATEGORIES:
            assert cat_name in CATEGORY_TARGET_LOCATIONS, \
                f"{cat_name} missing from CATEGORY_TARGET_LOCATIONS"

    def test_auth_priority_categories_subset(self):
        """AUTH_PRIORITY_CATEGORIES must be a subset of TECHNIQUE_CATEGORIES keys."""
        for cat in AUTH_PRIORITY_CATEGORIES:
            assert cat in TECHNIQUE_CATEGORIES, \
                f"AUTH_PRIORITY_CATEGORIES references unknown category: {cat}"


# ---------------------------------------------------------------------------
# A2: XSS reflected category
# ---------------------------------------------------------------------------

class TestXSSReflectedCategory:
    """A2: Verify XSS technique category structure and payload diversity."""

    def test_xss_reflected_category_exists(self):
        """A2: xss_reflected must be in TECHNIQUE_CATEGORIES."""
        assert "xss_reflected" in TECHNIQUE_CATEGORIES

    def test_xss_reflected_has_html_context_variants(self):
        """A2: html_context must contain script, img, svg, body variants."""
        variants = TECHNIQUE_CATEGORIES["xss_reflected"]["variants"]["html_context"]
        assert any("<script>" in v for v in variants)
        assert any("onerror" in v for v in variants)
        assert any("onload" in v for v in variants)

    def test_xss_reflected_has_attribute_breakout(self):
        """A2: attribute_breakout must contain quote-breakout payloads."""
        variants = TECHNIQUE_CATEGORIES["xss_reflected"]["variants"]["attribute_breakout"]
        assert any("<script>" in v for v in variants)
        assert any("onmouseover" in v or "onfocus" in v for v in variants)

    def test_xss_reflected_has_javascript_uri(self):
        """A2: javascript_uri must contain javascript: payloads."""
        variants = TECHNIQUE_CATEGORIES["xss_reflected"]["variants"]["javascript_uri"]
        assert all("javascript:" in v for v in variants)

    def test_xss_reflected_has_encoded_variants(self):
        """A2: encoded must contain URL-encoded and unicode-escaped payloads."""
        variants = TECHNIQUE_CATEGORIES["xss_reflected"]["variants"]["encoded"]
        assert any("%3Cscript%" in v for v in variants)
        assert any("\\u003c" in v for v in variants)

    def test_xss_reflected_has_polyglot(self):
        """A2: polyglot must contain at least one polyglot payload."""
        variants = TECHNIQUE_CATEGORIES["xss_reflected"]["variants"]["polyglot"]
        assert len(variants) >= 1


# ---------------------------------------------------------------------------
# A3: HTML injection category
# ---------------------------------------------------------------------------

class TestHtmlInjectionCategory:
    """A3: Verify HTML injection technique category structure."""

    def test_html_injection_category_exists(self):
        """A3: html_injection must be in TECHNIQUE_CATEGORIES."""
        assert "html_injection" in TECHNIQUE_CATEGORIES

    def test_html_injection_has_structural_variants(self):
        """A3: structural must contain diverse HTML elements."""
        variants = TECHNIQUE_CATEGORIES["html_injection"]["variants"]["structural"]
        assert any("<h1>" in v for v in variants)
        assert any("<img" in v for v in variants)
        assert any("<hr>" in v for v in variants)
        assert any("<iframe" in v for v in variants)


# ---------------------------------------------------------------------------
# P0-3: Generation-path regression tests
# ---------------------------------------------------------------------------


class TestDialectAgnosticFlag:
    """P0-3: Verify dialect_agnostic flag is set on categories with non-dialect variant keys."""

    def test_xss_reflected_is_dialect_agnostic(self):
        """P0-3: xss_reflected must be marked dialect_agnostic (variants keyed by html_context, etc., not dialect)."""
        assert TECHNIQUE_CATEGORIES["xss_reflected"].get("dialect_agnostic") is True

    def test_html_injection_is_dialect_agnostic(self):
        """P0-3: html_injection must be marked dialect_agnostic."""
        assert TECHNIQUE_CATEGORIES["html_injection"].get("dialect_agnostic") is True

    def test_path_traversal_is_dialect_agnostic(self):
        """P0-3: path_traversal must be marked dialect_agnostic (variants are OS-agnostic, not SQL-specific)."""
        assert TECHNIQUE_CATEGORIES["path_traversal"].get("dialect_agnostic") is True

    def test_non_dialect_agnostic_categories_are_not_flagged(self):
        """P0-3: Categories with dialect keys must NOT have dialect_agnostic flag."""
        for cat_name in ("comment_terminator", "tautology", "boolean_differential",
                         "time_based_blind", "union_based", "stacked_query"):
            assert TECHNIQUE_CATEGORIES[cat_name].get("dialect_agnostic") is not True, \
                f"{cat_name} should not have dialect_agnostic=True"


class TestGenerationPath:
    """P0-3: Every technique category must produce at least one PayloadCandidate via the real generator."""

    def _make_param(self, name="test", location="query"):
        from nagapasha.models.request_model import ParameterModel
        return ParameterModel(
            name=name,
            location=location,
            inferred_type="free_text",
            raw_value="testvalue",
            is_fuzz_target=True,
            do_not_fuzz=False,
        )

    def _make_req(self, dialect_hint=None, is_auth_endpoint=False):
        from nagapasha.models.request_model import RequestModel
        return RequestModel(
            method="GET",
            url="http://example.com/api/test",
            base_url="http://example.com",
            headers={"Host": "example.com"},
            dialect_hint=dialect_hint,
            is_auth_endpoint=is_auth_endpoint,
        )

    def _build_payloads(self, req, param):
        from nagapasha.cli import _build_technique_category_payloads
        return _build_technique_category_payloads(
            param=param,
            req=req,
            tech_stack=None,
            waf_detected=False,
            waf_name=None,
            dialect_hint=req.dialect_hint,
        )

    def test_every_technique_category_produces_at_least_one_candidate(self):
        """P0-3: Every category in TECHNIQUE_CATEGORIES must emit ≥1 PayloadCandidate.

        This is the structural regression test: if a new category is added with
        non-dialect variant keys (like xss_reflected was), and the generator is
        not updated to handle dialect_agnostic categories, this test fails.
        """
        req = self._make_req(dialect_hint=None)
        param = self._make_param()
        candidates = self._build_payloads(req, param)

        # Group candidates by attack_class
        by_class = {}
        for c in candidates:
            by_class.setdefault(c.attack_class, []).append(c)

        missing = []
        for cat_name in TECHNIQUE_CATEGORIES:
            if cat_name not in by_class or len(by_class[cat_name]) == 0:
                missing.append(cat_name)

        assert not missing, \
            f"Categories that produced 0 payloads: {missing}. " \
            "All categories must produce ≥1 candidate via the generator."

    def test_xss_reflected_emits_payloads(self):
        """P0-3: xss_reflected must emit payloads (proves the P0-1/P0-2 fix works)."""
        req = self._make_req()
        param = self._make_param()
        candidates = self._build_payloads(req, param)

        xss_candidates = [c for c in candidates if c.attack_class == "xss_reflected"]
        assert len(xss_candidates) >= 1, "xss_reflected must emit at least 1 payload"
        payload_texts = [c.payload for c in xss_candidates]
        # _fit_payload_for_param URL-encodes payloads — check for encoded <script>
        assert any("%3Cscript" in p or "<script>" in p for p in payload_texts)

    def test_html_injection_emits_payloads(self):
        """P0-3: html_injection must emit payloads (proves the P0-1/P0-2 fix works)."""
        req = self._make_req()
        param = self._make_param()
        candidates = self._build_payloads(req, param)

        html_candidates = [c for c in candidates if c.attack_class == "html_injection"]
        assert len(html_candidates) >= 1, "html_injection must emit at least 1 payload"
        payload_texts = [c.payload for c in html_candidates]
        # Check for encoded or raw <h1> payload
        assert any("%3Ch1" in p or "<h1>" in p for p in payload_texts)

    def test_path_traversal_emits_payloads(self):
        """P0-3: path_traversal must emit payloads (proves the P0-1/P0-2 fix works)."""
        req = self._make_req()
        param = self._make_param()
        candidates = self._build_payloads(req, param)

        pt_candidates = [c for c in candidates if c.attack_class == "path_traversal"]
        assert len(pt_candidates) >= 1, "path_traversal must emit at least 1 payload"
        payload_texts = [c.payload for c in pt_candidates]
        assert any("../../" in p for p in payload_texts)
