"""Tests for the payload deduplication module."""

import pytest

from nagapasha.engine.dedup import deduplicate_payloads, deduplication_stats
from nagapasha.engine.payload_loop import PayloadCandidate
from nagapasha.models.request_model import ParameterModel


def _make_candidate(param_name: str, location: str, payload: str) -> PayloadCandidate:
    """Helper to create a PayloadCandidate."""
    param = ParameterModel(
        name=param_name,
        location=location,
        raw_value="test",
        is_fuzz_target=True,
        inferred_type="free_text",
    )
    return PayloadCandidate(parameter=param, payload=payload, attack_class="test")


class TestDeduplicatePayloads:
    """Tests for deduplicate_payloads()."""

    def test_removes_exact_duplicates(self):
        """Should remove exact duplicate (param, location, payload) combos."""
        payloads = [
            _make_candidate("id", "query", "' OR 1=1"),
            _make_candidate("id", "query", "' OR 1=1"),
            _make_candidate("id", "query", "' OR 1=1"),
            _make_candidate("id", "query", "' OR 2=2"),
        ]
        result = deduplicate_payloads(payloads)
        assert len(result) == 2

    def test_preserves_different_params(self):
        """Should not dedup across different parameter names."""
        payloads = [
            _make_candidate("id", "query", "' OR 1=1"),
            _make_candidate("name", "query", "' OR 1=1"),
        ]
        result = deduplicate_payloads(payloads)
        assert len(result) == 2

    def test_preserves_different_locations(self):
        """Should not dedup across different parameter locations."""
        payloads = [
            _make_candidate("id", "query", "' OR 1=1"),
            _make_candidate("id", "body_json", "' OR 1=1"),
        ]
        result = deduplicate_payloads(payloads)
        assert len(result) == 2

    def test_empty_list(self):
        """Should return empty list for empty input."""
        result = deduplicate_payloads([])
        assert result == []

    def test_single_payload(self):
        """Should return single payload unchanged."""
        payloads = [_make_candidate("id", "query", "' OR 1=1")]
        result = deduplicate_payloads(payloads)
        assert len(result) == 1

    def test_all_unique(self):
        """Should return all payloads when no duplicates."""
        payloads = [
            _make_candidate("id", "query", "1"),
            _make_candidate("name", "query", "2"),
            _make_candidate("email", "body_json", "3"),
        ]
        result = deduplicate_payloads(payloads)
        assert len(result) == 3

    def test_mixed_duplicates_and_unique(self):
        """Should handle mix of duplicates and unique payloads."""
        payloads = [
            _make_candidate("id", "query", "1"),
            _make_candidate("id", "query", "2"),
            _make_candidate("id", "query", "1"),  # duplicate
            _make_candidate("name", "query", "3"),
            _make_candidate("name", "query", "3"),  # duplicate
        ]
        result = deduplicate_payloads(payloads)
        assert len(result) == 3

    def test_keeps_first_occurrence(self):
        """Should keep the first occurrence, not the last."""
        payloads = [
            _make_candidate("id", "query", "' OR 1=1"),
            _make_candidate("id", "query", "' OR 2=2"),
            _make_candidate("id", "query", "' OR 1=1"),  # dup of first
        ]
        result = deduplicate_payloads(payloads)
        assert result[0].payload == "' OR 1=1"
        assert result[1].payload == "' OR 2=2"


class TestIdentityHash:
    """Tests for identity hash generation."""

    def test_identity_hash_deterministic(self):
        """Test identity hash is deterministic."""
        from nagapasha.engine.payload_loop import compute_identity_hash

        h1 = compute_identity_hash("id", "query", "sql_injection", "' OR 1=1")
        h2 = compute_identity_hash("id", "query", "sql_injection", "' OR 1=1")
        assert h1 == h2

    def test_identity_hash_different_payloads(self):
        """Test different payloads produce different hashes."""
        from nagapasha.engine.payload_loop import compute_identity_hash

        h1 = compute_identity_hash("id", "query", "sql_injection", "' OR 1=1")
        h2 = compute_identity_hash("id", "query", "sql_injection", "' OR 2=2")
        assert h1 != h2

    def test_identity_hash_different_params(self):
        """Test different parameters produce different hashes."""
        from nagapasha.engine.payload_loop import compute_identity_hash

        h1 = compute_identity_hash("id", "query", "sql_injection", "' OR 1=1")
        h2 = compute_identity_hash("name", "query", "sql_injection", "' OR 1=1")
        assert h1 != h2

    def test_payload_candidate_auto_hash(self):
        """Test PayloadCandidate auto-computes identity_hash."""
        param = ParameterModel(
            name="id",
            location="query",
            inferred_type="int",
            raw_value="42",
            is_fuzz_target=True,
        )
        candidate = PayloadCandidate(
            parameter=param,
            payload="' OR 1=1",
            attack_class="sql_injection",
        )
        assert candidate.identity_hash != ""
        assert len(candidate.identity_hash) == 64


class TestDeduplicationStats:
    """Tests for deduplication_stats()."""

    def test_no_reduction(self):
        """Should report 0% reduction when no duplicates."""
        stats = deduplication_stats(original_count=100, deduplicated_count=100)
        assert stats["original_count"] == 100
        assert stats["deduplicated_count"] == 100
        assert stats["removed_count"] == 0
        assert stats["reduction_percent"] == 0.0

    def test_full_reduction(self):
        """Should report high reduction when mostly duplicates."""
        stats = deduplication_stats(original_count=100, deduplicated_count=1)
        assert stats["removed_count"] == 99
        assert stats["reduction_percent"] == 99.0

    def test_partial_reduction(self):
        """Should calculate correct reduction percentage."""
        stats = deduplication_stats(original_count=200, deduplicated_count=150)
        assert stats["removed_count"] == 50
        assert abs(stats["reduction_percent"] - 25.0) < 0.1
