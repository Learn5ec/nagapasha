"""Tests for the Phase 1 script generator."""

import pytest
from pathlib import Path
import tempfile

from nagapasha.engine.script_generator import StaticScriptGenerator, _sanitize_constant
from nagapasha.models.request_model import RequestModel, ParameterModel


class TestSanitizeConstant:
    def test_string(self):
        assert _sanitize_constant("hello") == "'hello'"
        assert _sanitize_constant("it's") == "\"it's\""

    def test_int(self):
        assert _sanitize_constant(42) == "42"
        assert _sanitize_constant(0) == "0"

    def test_float(self):
        assert _sanitize_constant(3.14) == "3.14"

    def test_bool(self):
        assert _sanitize_constant(True) == "True"
        assert _sanitize_constant(False) == "False"

    def test_none(self):
        assert _sanitize_constant(None) == "None"

    def test_list(self):
        result = _sanitize_constant([1, 2, 3])
        assert result == "[1, 2, 3]"

    def test_dict(self):
        result = _sanitize_constant({"a": 1, "b": 2})
        assert "'a': 1" in result
        assert "'b': 2" in result


class TestScriptGenerator:
    @pytest.fixture
    def sample_request(self):
        return RequestModel(
            method="GET",
            url="https://example.com/api/users?page=1",
            base_url="https://example.com",
            headers={"Authorization": "Bearer eyJ..."},
            cookies={"session": "abc123"},
            query_params={"page": "1"},
            parameters=[
                ParameterModel(
                    name="page",
                    location="query",
                    inferred_type="int",
                    raw_value="1",
                ),
            ],
            attack_specs=[
                {
                    "parameter": "page",
                    "placement": "full_replace",
                    "encoding": "none",
                    "payloads": ["1 UNION SELECT * FROM users--"],
                },
            ],
            engagement_id="test-001",
            rate_limit_config={"burst": 10, "refill_rate": 4.0},
            baseline_fingerprint={
                "status_code": 200,
                "content_length": 1234,
                "body_hash": "sha256:abc123def456",
                "avg_response_time": 0.045,
            },
        )

    def test_generate_creates_file(self, sample_request, tmp_path):
        generator = StaticScriptGenerator()
        output = tmp_path / "test_script.py"
        result = generator.generate(sample_request, output_path=output)
        assert result.exists()
        assert result == output

    def test_generate_contains_config(self, sample_request, tmp_path):
        generator = StaticScriptGenerator()
        output = tmp_path / "test_script.py"
        generator.generate(sample_request, output_path=output)
        content = output.read_text()

        assert "BASE_URL" in content
        assert "https://example.com" in content
        assert "METHOD" in content
        assert "PAYLOADS" in content

    def test_generate_contains_rate_limit(self, sample_request, tmp_path):
        generator = StaticScriptGenerator()
        output = tmp_path / "test_script.py"
        generator.generate(sample_request, output_path=output)
        content = output.read_text()

        assert "RATE_LIMIT_BURST" in content
        assert "RATE_LIMIT_RATE" in content

    def test_generate_contains_baseline(self, sample_request, tmp_path):
        generator = StaticScriptGenerator()
        output = tmp_path / "test_script.py"
        generator.generate(sample_request, output_path=output)
        content = output.read_text()

        assert "BASELINE_STATUS" in content
        assert "BASELINE_BODY_HASH" in content

    def test_generate_contains_attacks(self, sample_request, tmp_path):
        generator = StaticScriptGenerator()
        output = tmp_path / "test_script.py"
        generator.generate(sample_request, output_path=output)
        content = output.read_text()

        assert "1 UNION SELECT" in content

    def test_generate_default_path(self, sample_request):
        generator = StaticScriptGenerator()
        result = generator.generate(sample_request)
        assert "scripts" in str(result)
        assert "test-001" in str(result)
        assert result.name == "run_payloads.py"
        # Clean up
        result.unlink()

    def test_generated_script_is_valid_python(self, sample_request, tmp_path):
        """Verify the generated script is syntactically valid Python."""
        generator = StaticScriptGenerator()
        output = tmp_path / "test_script.py"
        generator.generate(sample_request, output_path=output)
        content = output.read_text()

        # Should compile without syntax errors
        try:
            compile(content, str(output), "exec")
        except SyntaxError as e:
            pytest.fail(f"Generated script has syntax error: {e}")
