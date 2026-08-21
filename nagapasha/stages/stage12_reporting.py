"""Stage 12 — Reporting.

Auto-generates findings report: parameter, attack type, payload, evidence,
confidence, WSTG reference, remediation.

Output: JSON + markdown report.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from nagapasha.engine.triage import TriageResult


class Report:
    """Findings report for an engagement."""

    def __init__(
        self,
        engagement_id: Optional[str] = None,
        target_url: Optional[str] = None,
        method: Optional[str] = None,
        findings: Optional[list[dict[str, Any]]] = None,
        summary: Optional[dict[str, Any]] = None,
    ) -> None:
        self.engagement_id = engagement_id
        self.target_url = target_url
        self.method = method
        self.findings = findings or []
        self.summary = summary or {}

    def add_finding(
        self,
        parameter_name: str,
        attack_class: str,
        payload: str,
        evidence: str,
        confidence: float,
        wstg_reference: Optional[str] = None,
        remediation: Optional[str] = None,
        request_raw: Optional[str] = None,
        response_raw: Optional[str] = None,
    ) -> None:
        """Add a finding to the report.

        Args:
            parameter_name: Target parameter name
            attack_class: Attack class (e.g., "sql_injection")
            payload: Payload that triggered the finding
            evidence: Evidence description
            confidence: Confidence level (0.0 to 1.0)
            wstg_reference: OWASP WSTG reference
            remediation: Remediation advice
            request_raw: Raw request (for chain of custody)
            response_raw: Raw response (for chain of custody)
        """
        from nagapasha.security.redact import redact_text
        import hashlib

        # Stage 13: Redact PII/secrets from evidence
        redacted_evidence = redact_text(evidence)
        redacted_payload = redact_text(payload)

        # Stage 13: Hash evidence for chain of custody
        evidence_hash = ""
        if request_raw and response_raw:
            evidence_data = f"{request_raw}|{response_raw}".encode()
            evidence_hash = hashlib.sha256(evidence_data).hexdigest()

        self.findings.append({
            "parameter_name": parameter_name,
            "attack_class": attack_class,
            "payload": redacted_payload,
            "evidence": redacted_evidence,
            "confidence": confidence,
            "wstg_reference": wstg_reference or "N/A",
            "remediation": remediation or self._default_remediation(attack_class),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "evidence_hash": evidence_hash,
            "engagement_id": self.engagement_id,
        })

    def to_json(self) -> str:
        """Serialize report to JSON."""
        return json.dumps({
            "engagement_id": self.engagement_id,
            "target_url": self.target_url,
            "method": self.method,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "summary": self.summary,
            "findings": self.findings,
        }, indent=2)

    def to_sarif(self) -> str:
        """Generate SARIF (Static Analysis Results Interchange Format) report.

        SARIF is an OASIS standard for representing static analysis results.
        """
        # Build unique rules list
        rules = []
        seen_rules = set()
        for finding in self.findings:
            rule_id = finding["attack_class"]
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {
                        "text": rule_id,
                    },
                })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "nagapasha",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/nagapasha",
                            "rules": rules,
                        }
                    },
                    "results": [
                        {
                            "ruleId": finding["attack_class"],
                            "level": "error" if finding["confidence"] >= 0.8 else "warning",
                            "message": {
                                "text": f"Parameter '{finding['parameter_name']}' vulnerable to {finding['attack_class']}",
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "region": {
                                            "startColumn": 1,
                                        },
                                    },
                                }
                            ],
                        }
                        for finding in self.findings
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def to_junit(self) -> str:
        """Generate JUnit XML report.

        JUnit XML is a standard format for test results, commonly used in CI/CD.
        """
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<testsuite',
            f'  name="nagapasha-{self.engagement_id or "unknown"}"',
            f'  tests="{len(self.findings)}"',
            f'  failures="{sum(1 for f in self.findings if f.get("confidence", 0) >= 0.8)}"',
            f'  errors="0"',
            f'  time="{sum(f.get("elapsed", 0) for f in self.findings):.2f}"',
            '>',
        ]

        for finding in self.findings:
            severity = "high" if finding.get("confidence", 0) >= 0.8 else "medium"
            lines.extend([
                f'  <testcase',
                f'    classname="nagapasha.{finding["attack_class"]}"',
                f'    name="{finding["parameter_name"]}"',
                f'    time="{finding.get("elapsed", 0):.2f}"',
                f'  >',
                f'    <failure message="{finding["attack_class"]}" type="{severity}">',
                f'      Parameter: {finding["parameter_name"]}',
                f'      Payload: {finding["payload"][:100]}',
                f'      Confidence: {finding.get("confidence", 0):.0%}',
                f'      Evidence: {finding.get("evidence", "")[:200]}',
                f'    </failure>',
                f'  </testcase>',
            ])

        lines.append('</testsuite>')
        return "\n".join(lines)

    def to_html(self) -> str:
        """Generate HTML report with findings table."""
        html = [
            "<!DOCTYPE html>",
            "<html lang=\"en\">",
            "<head>",
            "  <meta charset=\"UTF-8\">",
            "  <title>nagapasha Report</title>",
            "  <style>",
            "    body { font-family: Arial, sans-serif; margin: 2rem; }",
            "    h1 { color: #333; }",
            "    table { border-collapse: collapse; width: 100%; margin-top: 1rem; }",
            "    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "    th { background-color: #4CAF50; color: white; }",
            "    tr:nth-child(even) { background-color: #f2f2f2; }",
            "    .confirmed { color: #d32f2f; font-weight: bold; }",
            "    .near_miss { color: #f57c00; }",
            "  </style>",
            "</head>",
            "<body>",
            "  <h1>nagapasha Security Report</h1>",
            f"  <p><strong>Engagement:</strong> {self.engagement_id or 'N/A'}</p>",
            f"  <p><strong>Target:</strong> {self.target_url or 'N/A'}</p>",
            f"  <p><strong>Method:</strong> {self.method or 'N/A'}</p>",
            f"  <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>",
            "  <h2>Findings</h2>",
            "  <table>",
            "    <tr>",
            "      <th>Parameter</th>",
            "      <th>Attack Class</th>",
            "      <th>Payload</th>",
            "      <th>Confidence</th>",
            "      <th>Evidence</th>",
            "      <th>Severity</th>",
            "    </tr>",
        ]

        for finding in self.findings:
            severity = "confirmed" if finding.get("confidence", 0) >= 0.8 else "near_miss"
            html.extend([
                "    <tr>",
                f"      <td>{finding['parameter_name']}</td>",
                f"      <td>{finding['attack_class']}</td>",
                f"      <td><code>{finding['payload'][:50]}</code></td>",
                f"      <td>{finding.get('confidence', 0):.0%}</td>",
                f"      <td>{finding.get('evidence', '')[:100]}</td>",
                f"      <td class=\"{severity}\">{severity}</td>",
                "    </tr>",
            ])

        html.extend([
            "  </table>",
            "</body>",
            "</html>",
        ])

        return "\n".join(html)

    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            f"# Security Testing Report",
            f"",
            f"**Engagement ID:** {self.engagement_id or 'N/A'}",
            f"**Target:** {self.target_url or 'N/A'}",
            f"**Method:** {self.method or 'N/A'}",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"",
            f"## Summary",
            f"",
        ]

        # Summary stats
        total = len(self.findings)
        confirmed = sum(1 for f in self.findings if f.get("confidence", 0) >= 0.8)
        inconclusive = sum(1 for f in self.findings if f.get("confidence", 0) < 0.5)
        lines.append(f"- **Total findings:** {total}")
        lines.append(f"- **Confirmed:** {confirmed}")
        lines.append(f"- **Inconclusive:** {inconclusive}")
        lines.append(f"")

        if not self.findings:
            lines.append("No confirmed findings.")
            return "\n".join(lines)

        lines.append("## Findings")
        lines.append("")

        for i, finding in enumerate(self.findings, 1):
            lines.append(f"### Finding #{i}: {finding['attack_class']}")
            lines.append("")
            lines.append(f"- **Parameter:** `{finding['parameter_name']}`")
            lines.append(f"- **Payload:** `{finding['payload'][:100]}`")
            lines.append(f"- **Confidence:** {finding['confidence']:.0%}")
            lines.append(f"- **WSTG:** {finding['wstg_reference']}")
            lines.append(f"- **Evidence:** {finding['evidence']}")
            lines.append(f"- **Remediation:** {finding['remediation']}")
            lines.append("")

        return "\n".join(lines)

    def save(self, output_dir: Path, format: str = "all") -> list[Path]:
        """Save report to output directory.

        Args:
            output_dir: Directory to save reports.
            format: Output format(s) - "all", "json", "markdown", "sarif", "junit", "html".

        Returns:
            List of saved file paths.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        eid = self.engagement_id or "report"
        paths = []

        if format in ("all", "json"):
            json_path = output_dir / f"{eid}_report.json"
            json_path.write_text(self.to_json())
            paths.append(json_path)

        if format in ("all", "markdown"):
            md_path = output_dir / f"{eid}_report.md"
            md_path.write_text(self.to_markdown())
            paths.append(md_path)

        if format in ("all", "sarif"):
            sarif_path = output_dir / f"{eid}_report.sarif"
            sarif_path.write_text(self.to_sarif())
            paths.append(sarif_path)

        if format in ("all", "junit"):
            junit_path = output_dir / f"{eid}_report.xml"
            junit_path.write_text(self.to_junit())
            paths.append(junit_path)

        if format in ("all", "html"):
            html_path = output_dir / f"{eid}_report.html"
            html_path.write_text(self.to_html())
            paths.append(html_path)

        return paths

    @staticmethod
    def _default_remediation(attack_class: str) -> str:
        """Return default remediation advice for an attack class."""
        remediation_map = {
            "sql_injection": "Use parameterized queries. Validate and sanitize all input.",
            "xss": "Encode output. Use Content-Security-Policy headers. Validate input.",
            "lfi": "Use allowlists for file paths. Chroot sandboxes. Remove unnecessary file access.",
            "idor": "Implement proper access controls. Verify ownership on every request.",
            "ssrf": "Whitelist allowed destinations. Use egress filtering. Disable unnecessary services.",
            "path_traversal": "Validate and sanitize file paths. Use chroot. Reject '../' sequences.",
            "command_injection": "Avoid passing user input to system commands. Use parameterized APIs.",
            "xxe": "Disable DTD processing. Use XML parsers that don't process external entities.",
            "generic_injection": "Apply input validation, output encoding, and parameterized queries.",
        }
        return remediation_map.get(attack_class, "Review and apply appropriate security controls.")
