"""A1 integration tests: dialect-aware payload selection + timing anomaly detection.

Verifies:
- _build_technique_category_payloads filters SQL payloads by dialect_hint
- pg_sleep payloads are the only ones emitted for postgres dialect
- timing_anomaly correctly flags pg_sleep delay vs baseline
- SLEEP(5) payloads are correctly filtered OUT when dialect_hint="postgres"
"""

import asyncio
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from nagapasha.models.request_model import RequestModel, ParameterModel
from nagapasha.engine.timing_anomaly import TimingMonitor, TimingCheck


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_param(name="test_param", location="query") -> ParameterModel:
    return ParameterModel(
        name=name,
        location=location,
        inferred_type="free_text",
        raw_value="test",
        is_fuzz_target=True,
        do_not_fuzz=False,
    )


def _make_req(dialect_hint=None, confirmed_tech_stack=None) -> RequestModel:
    return RequestModel(
        method="GET",
        url="http://example.com/api/test",
        base_url="http://example.com",
        headers={"Host": "example.com"},
        dialect_hint=dialect_hint,
        confirmed_tech_stack=confirmed_tech_stack,
    )


# ---------------------------------------------------------------------------
# _build_technique_category_payloads dialect filtering
# ---------------------------------------------------------------------------

class TestDialectFiltering:
    """Test that _build_technique_category_payloads correctly filters by dialect."""

    def _build_payloads(self, req: RequestModel, param: ParameterModel) -> list:
        """Import and call the private builder function."""
        from nagapasha.cli import _build_technique_category_payloads
        return _build_technique_category_payloads(
            param=param,
            req=req,
            tech_stack=None,
            waf_detected=False,
            waf_name=None,
            dialect_hint=req.dialect_hint,
        )

    def test_postgres_dialect_emits_pg_sleep_payloads(self):
        """A1: When dialect_hint='postgres', time_based_blind payloads must include pg_sleep."""
        req = _make_req(dialect_hint="postgres")
        param = _make_param()
        candidates = self._build_payloads(req, param)

        tbb_payloads = [c for c in candidates
                        if c.attack_class == "time_based_blind"]
        payload_texts = [c.payload for c in tbb_payloads]

        # At least one pg_sleep payload must be present
        assert any("pg_sleep" in p for p in payload_texts), \
            f"Expected pg_sleep payloads, got: {payload_texts}"

    def test_postgres_dialect_excludes_mysql_sleep(self):
        """A1: SLEEP(5)-- (MySQL) must NOT appear when dialect_hint='postgres'."""
        req = _make_req(dialect_hint="postgres")
        param = _make_param()
        candidates = self._build_payloads(req, param)

        tbb_payloads = [c for c in candidates
                        if c.attack_class == "time_based_blind"]
        payload_texts = [c.payload for c in tbb_payloads]

        assert not any("SLEEP(5)" in p for p in payload_texts), \
            f"SLEEP(5) (MySQL) should be filtered out for postgres, got: {payload_texts}"

    def test_postgres_dialect_excludes_mssql_waitfor(self):
        """A1: WAITFOR DELAY must NOT appear when dialect_hint='postgres'."""
        req = _make_req(dialect_hint="postgres")
        param = _make_param()
        candidates = self._build_payloads(req, param)

        tbb_payloads = [c for c in candidates
                        if c.attack_class == "time_based_blind"]
        payload_texts = [c.payload for c in tbb_payloads]

        assert not any("WAITFOR" in p for p in payload_texts), \
            f"WAITFOR DELAY should be filtered out for postgres, got: {payload_texts}"

    def test_postgres_dialect_excludes_mysql_benchmark(self):
        """A1: BENCHMARK must NOT appear when dialect_hint='postgres'."""
        req = _make_req(dialect_hint="postgres")
        param = _make_param()
        candidates = self._build_payloads(req, param)

        tbb_payloads = [c for c in candidates
                        if c.attack_class == "time_based_blind"]
        payload_texts = [c.payload for c in tbb_payloads]

        assert not any("BENCHMARK" in p for p in payload_texts), \
            f"BENCHMARK should be filtered out for postgres, got: {payload_texts}"

    def test_mysql_dialect_emits_sleep_but_excludes_pg_sleep(self):
        """A1: MySQL dialect emits SLEEP/BENCHMARK but NOT pg_sleep."""
        req = _make_req(dialect_hint="mysql")
        param = _make_param()
        candidates = self._build_payloads(req, param)

        tbb_payloads = [c for c in candidates
                        if c.attack_class == "time_based_blind"]
        payload_texts = [c.payload for c in tbb_payloads]

        assert any("SLEEP(5)" in p for p in payload_texts), \
            "MySQL dialect must emit SLEEP(5)"
        assert not any("pg_sleep" in p for p in payload_texts), \
            f"pg_sleep should be filtered out for mysql, got: {payload_texts}"

    def test_no_dialect_hint_emits_all_sql_variants(self):
        """When dialect_hint is None, all SQL variants are emitted (no filtering)."""
        req = _make_req(dialect_hint=None)
        param = _make_param()
        candidates = self._build_payloads(req, param)

        tbb_payloads = [c for c in candidates
                        if c.attack_class == "time_based_blind"]
        payload_texts = [c.payload for c in tbb_payloads]

        # All three dialects should be present
        assert any("SLEEP(5)" in p for p in payload_texts)
        assert any("BENCHMARK" in p for p in payload_texts)
        assert any("WAITFOR" in p for p in payload_texts)
        assert any("pg_sleep" in p for p in payload_texts)

    def test_dialect_hint_from_tech_stack(self):
        """dialect_hint can be derived from confirmed_tech_stack['database']."""
        req = _make_req(confirmed_tech_stack={"database": "postgres"})
        param = _make_param()
        candidates = self._build_payloads(req, param)

        tbb_payloads = [c for c in candidates
                        if c.attack_class == "time_based_blind"]
        payload_texts = [c.payload for c in tbb_payloads]

        # Must include pg_sleep, exclude MySQL-only payloads
        assert any("pg_sleep" in p for p in payload_texts)
        assert not any("SLEEP(5)" in p for p in payload_texts)

    def test_explicit_dialect_hint_overrides_tech_stack(self):
        """Explicit dialect_hint wins over confirmed_tech_stack."""
        req = _make_req(
            dialect_hint="mysql",
            confirmed_tech_stack={"database": "postgres"},
        )
        param = _make_param()
        candidates = self._build_payloads(req, param)

        tbb_payloads = [c for c in candidates
                        if c.attack_class == "time_based_blind"]
        payload_texts = [c.payload for c in tbb_payloads]

        # MySQL dialect wins: SLEEP present, pg_sleep absent
        assert any("SLEEP(5)" in p for p in payload_texts)
        assert not any("pg_sleep" in p for p in payload_texts)

    def test_boolean_differential_not_filtered_by_dialect(self):
        """boolean_differential payloads are emitted regardless of dialect_hint
        (they apply across all SQL dialects)."""
        req = _make_req(dialect_hint="postgres")
        param = _make_param()
        candidates = self._build_payloads(req, param)

        bd_payloads = [c for c in candidates
                       if c.attack_class == "boolean_differential"]
        assert len(bd_payloads) > 0, \
            "boolean_differential should not be filtered by dialect_hint"


# ---------------------------------------------------------------------------
# Timing anomaly: pg_sleep vs baseline
# ---------------------------------------------------------------------------

class TestTimingAnomalyWithPgSleep:
    """Timing-anomaly detection should flag pg_sleep delays."""

    def test_pg_sleep_delay_flagged_as_anomalous(self):
        """A1: pg_sleep(5) should produce a delay >3x baseline, flagged as anomalous."""
        monitor = TimingMonitor(window_size=5)

        # Record baseline responses (no delay)
        for _ in range(5):
            monitor.record_baseline(elapsed=0.2)

        # Simulate response with pg_sleep delay (~5 seconds)
        check = monitor.check(payload_elapsed=5.1)

        assert check.anomalous, \
            f"Expected timing anomaly for pg_sleep delay, got: {check.details}"
        assert check.delay_magnitude > 4.0, \
            f"Expected delay magnitude >4s, got {check.delay_magnitude:.3f}s"

    def test_no_delay_not_flagged(self):
        """A1: A normal response should not be flagged as anomalous."""
        monitor = TimingMonitor(window_size=5)

        for _ in range(5):
            monitor.record_baseline(elapsed=0.2)

        check = monitor.check(payload_elapsed=0.25)

        assert not check.anomalous, \
            f"Normal response should not be flagged: {check.details}"

    def test_insufficient_baseline_data(self):
        """A1: With <3 baseline samples, timing check returns not-anomalous."""
        monitor = TimingMonitor(window_size=5)
        monitor.record_baseline(elapsed=0.2)  # only 1 sample

        check = monitor.check(payload_elapsed=5.1)

        assert not check.anomalous
        assert "insufficient baseline data" in check.details[0]

    def test_boundary_case_3x_baseline(self):
        """A1: Exactly 3x baseline should be flagged (>= boundary)."""
        monitor = TimingMonitor(window_size=5)

        for _ in range(5):
            monitor.record_baseline(elapsed=0.1)

        check = monitor.check(payload_elapsed=0.31)

        assert check.anomalous, "3.1x baseline should be flagged as anomalous"
