"""Tests for all report output formats (SARIF, JUnit, HTML)."""

import json
import pytest
from pathlib import Path

from nagapasha.stages.stage12_reporting import Report


@pytest.fixture
def report_with_findings():
    """Create a report with sample findings."""
    report = Report(
        engagement_id="test-456",
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
    report.add_finding(
        parameter_name="name",
        attack_class="xss",
        payload="<script>alert(1)</script>",
        evidence="Payload reflected in response",
        confidence=0.7,
        wstg_reference="WSTG-INPV-05",
    )
    return report


class TestSARIF:
    """Tests for SARIF output format."""

    def test_to_sarif_basic(self, report_with_findings):
        """Should generate valid SARIF JSON."""
        sarif = report_with_findings.to_sarif()
        data = json.loads(sarif)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1

    def test_sarif_rules_deduplicated(self, report_with_findings):
        """Should deduplicate rules by attack class."""
        sarif = report_with_findings.to_sarif()
        data = json.loads(sarif)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert len(rule_ids) == len(set(rule_ids))  # no duplicates
        assert "sql_injection" in rule_ids
        assert "xss" in rule_ids

    def test_sarif_results_count(self, report_with_findings):
        """Should have one result per finding."""
        sarif = report_with_findings.to_sarif()
        data = json.loads(sarif)
        results = data["runs"][0]["results"]
        assert len(results) == 2

    def test_sarif_high_confidence_level(self, report_with_findings):
        """Should use 'error' level for high confidence."""
        sarif = report_with_findings.to_sarif()
        data = json.loads(sarif)
        results = data["runs"][0]["results"]
        sql_finding = next(r for r in results if r["ruleId"] == "sql_injection")
        assert sql_finding["level"] == "error"  # 0.95 >= 0.8

    def test_sarif_low_confidence_level(self, report_with_findings):
        """Should use 'warning' level for lower confidence."""
        sarif = report_with_findings.to_sarif()
        data = json.loads(sarif)
        results = data["runs"][0]["results"]
        xss_finding = next(r for r in results if r["ruleId"] == "xss")
        assert xss_finding["level"] == "warning"  # 0.7 < 0.8

    def test_sarif_empty_report(self):
        """Should handle empty report."""
        report = Report()
        sarif = report.to_sarif()
        data = json.loads(sarif)
        assert len(data["runs"][0]["results"]) == 0


class TestJUnit:
    """Tests for JUnit XML output format."""

    def test_to_junit_basic(self, report_with_findings):
        """Should generate valid JUnit XML."""
        junit = report_with_findings.to_junit()
        assert '<?xml version="1.0"' in junit
        assert "<testsuite" in junit
        assert "nagapasha-test-456" in junit

    def test_junit_failure_count(self, report_with_findings):
        """Should count failures for high confidence findings."""
        junit = report_with_findings.to_junit()
        assert 'failures="1"' in junit

    def test_junit_testcase_count(self, report_with_findings):
        """Should have one testcase per finding."""
        junit = report_with_findings.to_junit()
        assert junit.count("<testcase") == 2


class TestHTML:
    """Tests for HTML output format."""

    def test_to_html_basic(self, report_with_findings):
        """Should generate valid HTML."""
        html = report_with_findings.to_html()
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "nagapasha Security Report" in html

    def test_html_contains_findings(self, report_with_findings):
        """Should contain finding details in HTML."""
        html = report_with_findings.to_html()
        assert "sql_injection" in html
        assert "<script>alert(1)</script>" in html

    def test_html_empty_report(self):
        """Should handle empty report."""
        report = Report()
        html = report.to_html()
        assert "<!DOCTYPE html>" in html
        assert "nagapasha Security Report" in html


class TestSaveFormats:
    """Tests for save() with different format options."""

    def test_save_all(self, tmp_path):
        """Should save all formats when format='all'."""
        report = Report(engagement_id="test")
        report.add_finding(
            parameter_name="id",
            attack_class="sql_injection",
            payload="' OR 1=1",
            evidence="error",
            confidence=0.95,
        )
        paths = report.save(tmp_path, format="all")
        suffixes = {p.suffix for p in paths}
        assert ".json" in suffixes
        assert ".md" in suffixes
        assert ".sarif" in suffixes
        assert ".xml" in suffixes
        assert ".html" in suffixes

    def test_save_json_only(self, tmp_path):
        """Should save only JSON when format='json'."""
        report = Report(engagement_id="test")
        report.add_finding(
            parameter_name="id",
            attack_class="sql_injection",
            payload="' OR 1=1",
            evidence="error",
            confidence=0.95,
        )
        paths = report.save(tmp_path, format="json")
        suffixes = {p.suffix for p in paths}
        assert suffixes == {".json"}

    def test_save_markdown_only(self, tmp_path):
        """Should save only markdown when format='markdown'."""
        report = Report(engagement_id="test")
        report.add_finding(
            parameter_name="id",
            attack_class="sql_injection",
            payload="' OR 1=1",
            evidence="error",
            confidence=0.95,
        )
        paths = report.save(tmp_path, format="markdown")
        suffixes = {p.suffix for p in paths}
        assert suffixes == {".md"}

    def test_save_sarif_only(self, tmp_path):
        """Should save only SARIF when format='sarif'."""
        report = Report(engagement_id="test")
        report.add_finding(
            parameter_name="id",
            attack_class="sql_injection",
            payload="' OR 1=1",
            evidence="error",
            confidence=0.95,
        )
        paths = report.save(tmp_path, format="sarif")
        suffixes = {p.suffix for p in paths}
        assert suffixes == {".sarif"}

    def test_save_junit_only(self, tmp_path):
        """Should save only JUnit when format='junit'."""
        report = Report(engagement_id="test")
        report.add_finding(
            parameter_name="id",
            attack_class="sql_injection",
            payload="' OR 1=1",
            evidence="error",
            confidence=0.95,
        )
        paths = report.save(tmp_path, format="junit")
        suffixes = {p.suffix for p in paths}
        assert suffixes == {".xml"}

    def test_save_html_only(self, tmp_path):
        """Should save only HTML when format='html'."""
        report = Report(engagement_id="test")
        report.add_finding(
            parameter_name="id",
            attack_class="sql_injection",
            payload="' OR 1=1",
            evidence="error",
            confidence=0.95,
        )
        paths = report.save(tmp_path, format="html")
        suffixes = {p.suffix for p in paths}
        assert suffixes == {".html"}
