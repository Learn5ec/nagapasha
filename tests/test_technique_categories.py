"""Tests for nagapasha/utils/technique_categories.py

Verifies:
- All expected categories exist
- time_based_blind contains Postgres-specific pg_sleep variants (A1 fix)
- Tuples carry dialect tags
- AUTH_PRIORITY_CATEGORIES covers auth-endpoint credential fields
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
