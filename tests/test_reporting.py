"""Tests for the Reporting stage (Stage 12)."""

import json
import pytest
from pathlib import Path

from nagapasha.stages.stage12_reporting import Report


class TestReport:
    def test_add_finding(self):
        """Should add a finding to the report."""
        report = Report(
            engagement_id="test-123",
            target_url="https://example.com/api",
            method="GET",
        )
        report.add_finding(
            parameter_name="id",
            attack_class="sql_injection",
            payload="' OR 1=1",
            evidence="MySQL error in response",
            confidence=0.95,
            wstg_reference="WSTG-INPV-08",
        )
        assert len(report.findings) == 1
        assert report.findings[0]["parameter_name"] == "id"
        assert report.findings[0]["attack_class"] == "sql_injection"

    def test_to_json(self):
        """Should serialize to valid JSON."""
        report = Report(
            engagement_id="test-123",
            target_url="https://example.com/api",
            method="GET",
        )
        report.add_finding(
            parameter_name="id",
            attack_class="sql_injection",
            payload="' OR 1=1",
            evidence="MySQL error",
            confidence=0.95,
        )
        j = report.to_json()
        data = json.loads(j)
        assert data["engagement_id"] == "test-123"
        assert len(data["findings"]) == 1

    def test_to_markdown(self):
        """Should generate markdown report."""
        report = Report(
            engagement_id="test-123",
            target_url="https://example.com/api",
            method="GET",
        )
        report.add_finding(
            parameter_name="id",
            attack_class="sql_injection",
            payload="' OR 1=1",
            evidence="MySQL error",
            confidence=0.95,
        )
        md = report.to_markdown()
        assert "# Security Testing Report" in md
        assert "Finding #1" in md
        assert "sql_injection" in md
        assert "id" in md

    def test_to_markdown_no_findings(self):
        """Should handle empty findings gracefully."""
        report = Report()
        md = report.to_markdown()
        assert "No confirmed findings" in md

    def test_save(self, tmp_path):
        """Should save JSON and markdown to output directory."""
        report = Report(
            engagement_id="test-123",
            target_url="https://example.com/api",
            method="GET",
        )
        report.add_finding(
            parameter_name="id",
            attack_class="sql_injection",
            payload="' OR 1=1",
            evidence="MySQL error",
            confidence=0.95,
        )

        paths = report.save(tmp_path)
        assert len(paths) >= 2  # At least JSON and markdown

        # Find JSON and markdown paths
        json_path = next((p for p in paths if p.suffix == ".json"), None)
        md_path = next((p for p in paths if p.suffix == ".md"), None)
        assert json_path is not None
        assert md_path is not None
        assert json_path.exists()
        assert md_path.exists()

        # Verify contents
        json_data = json.loads(json_path.read_text())
        assert json_data["engagement_id"] == "test-123"

        md_content = md_path.read_text()
        assert "sql_injection" in md_content

    def test_default_remediation(self):
        """Should return appropriate remediation for known attack classes."""
        report = Report()
        assert "parameterized" in report._default_remediation("sql_injection").lower()
        assert "Content-Security-Policy" in report._default_remediation("xss")
        assert "allowlist" in report._default_remediation("lfi").lower()
