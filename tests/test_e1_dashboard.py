"""E1 tests: Dashboard web interface (dashboard).

Verifies:
- NagapashaDashboard initialization
- API routes return correct data
- HTML rendering
- Scan status updates
- Endpoint, finding, session summaries
"""

import json
import pytest
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi.testclient import TestClient

from nagapasha.dashboard import NagapashaDashboard, DashboardData
from nagapasha.dashboard import EndpointSummary, FindingSummary, SessionSummary, ScanStatus


# ---------------------------------------------------------------------------
# Pydantic model tests
# ---------------------------------------------------------------------------


class TestEndpointSummary:
    """E1: EndpointSummary model."""

    def test_endpoint_summary_creation(self):
        """E1: EndpointSummary must be creatable."""
        ep = EndpointSummary(
            method="GET",
            path_template="/users/{id}",
            concrete_path="/users/1",
            risk_tags=["auth", "write"],
            parameter_count=2,
        )
        assert ep.method == "GET"
        assert ep.risk_tags == ["auth", "write"]
        assert ep.parameter_count == 2


class TestFindingSummary:
    """E1: FindingSummary model."""

    def test_finding_summary_creation(self):
        """E1: FindingSummary must be creatable."""
        f = FindingSummary(
            type="xss_reflected",
            severity="high",
            confidence=0.95,
            endpoint="/users/{id}",
            description="XSS in user ID parameter",
        )
        assert f.type == "xss_reflected"
        assert f.severity == "high"
        assert f.confidence == 0.95


class TestSessionSummary:
    """E1: SessionSummary model."""

    def test_session_summary_creation(self):
        """E1: SessionSummary must be creatable."""
        s = SessionSummary(
            label="admin",
            session_id="abc123",
            expires_at=datetime.now(timezone.utc),
            cookies=["session", "token"],
            auth_header="Bearer token",
        )
        assert s.label == "admin"
        assert len(s.cookies) == 2


class TestScanStatus:
    """E1: ScanStatus model."""

    def test_scan_status_default(self):
        """E1: ScanStatus must have sensible defaults."""
        s = ScanStatus(is_running=False)
        assert s.endpoints_found == 0
        assert s.findings_count == 0


class TestDashboardData:
    """E1: DashboardData model."""

    def test_dashboard_data_creation(self):
        """E1: DashboardData must be creatable."""
        d = DashboardData(
            scan_status=ScanStatus(is_running=False),
            endpoints=[],
            findings=[],
            sessions=[],
            spec_urls=[],
        )
        assert d.scan_status.is_running is False


# ---------------------------------------------------------------------------
# NagapashaDashboard
# ---------------------------------------------------------------------------


class TestNagapashaDashboard:
    """E1: NagapashaDashboard class."""

    def test_dashboard_creation(self):
        """E1: Dashboard must be creatable."""
        dashboard = NagapashaDashboard()
        assert dashboard.app is not None
        assert dashboard.scan_results is None

    def test_dashboard_update_scan(self):
        """E1: Dashboard must update scan results."""
        dashboard = NagapashaDashboard()
        dashboard.update_scan({"total_endpoints": 10, "total_findings": 3})
        assert dashboard.scan_results["total_endpoints"] == 10

    def test_get_status_no_results(self):
        """E1: Status must show idle when no results."""
        dashboard = NagapashaDashboard()
        client = TestClient(dashboard.app)
        response = client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert data["is_running"] is False
        assert data["endpoints_found"] == 0

    def test_get_status_with_results(self):
        """E1: Status must show correct counts with results."""
        dashboard = NagapashaDashboard()
        dashboard.scan_results = {
            "total_endpoints": 10,
            "total_findings": 3,
            "total_sessions": 2,
            "total_bola_checks": 5,
            "total_errors": [],
        }
        client = TestClient(dashboard.app)
        response = client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert data["endpoints_found"] == 10
        assert data["findings_count"] == 3
        assert data["sessions_count"] == 2

    def test_get_endpoints_no_results(self):
        """E1: Endpoints must be empty when no results."""
        dashboard = NagapashaDashboard()
        client = TestClient(dashboard.app)
        response = client.get("/api/endpoints")
        assert response.status_code == 200
        data = response.json()
        assert data == []

    def test_get_endpoints_with_results(self):
        """E1: Endpoints must be returned with results."""
        dashboard = NagapashaDashboard()
        dashboard.scan_results = {
            "endpoints": [
                {
                    "method": "GET",
                    "path_template": "/users/{id}",
                    "concrete_path": "/users/1",
                    "risk_tags": ["auth"],
                    "parameters": [
                        {"name": "id", "location": "path", "inferred_type": "int", "raw_value": "1"},
                    ],
                }
            ],
        }
        client = TestClient(dashboard.app)
        response = client.get("/api/endpoints")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["method"] == "GET"
        assert data[0]["path_template"] == "/users/{id}"

    def test_get_findings_no_results(self):
        """E1: Findings must be empty when no results."""
        dashboard = NagapashaDashboard()
        client = TestClient(dashboard.app)
        response = client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert data == []

    def test_get_findings_with_results(self):
        """E1: Findings must be returned with results."""
        dashboard = NagapashaDashboard()
        dashboard.scan_results = {
            "findings": [
                {
                    "type": "xss_reflected",
                    "severity": "high",
                    "confidence": 0.95,
                    "endpoint": "/users/{id}",
                    "description": "XSS in user ID",
                }
            ],
        }
        client = TestClient(dashboard.app)
        response = client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["type"] == "xss_reflected"
        assert data[0]["severity"] == "high"

    def test_get_sessions_no_results(self):
        """E1: Sessions must be empty when no results."""
        dashboard = NagapashaDashboard()
        client = TestClient(dashboard.app)
        response = client.get("/api/sessions")
        assert response.status_code == 200
        data = response.json()
        assert data == []

    def test_get_sessions_with_results(self):
        """E1: Sessions must be returned with results."""
        from nagapasha.session.session_manager import SessionContext

        dashboard = NagapashaDashboard()
        dashboard.scan_results = {
            "sessions": [
                SessionContext(label="admin", session_id="abc123", cookies={"session": "xyz"}),
            ],
        }
        client = TestClient(dashboard.app)
        response = client.get("/api/sessions")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["label"] == "admin"

    def test_index_page(self):
        """E1: Index page must return HTML."""
        dashboard = NagapashaDashboard()
        client = TestClient(dashboard.app)
        response = client.get("/")
        assert response.status_code == 200
        assert "nagapasha" in response.text

    def test_openapi_docs(self):
        """E1: OpenAPI docs must be available."""
        dashboard = NagapashaDashboard()
        client = TestClient(dashboard.app)
        response = client.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "paths" in data
        assert "/api/status" in data["paths"]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """E1: Edge case tests."""

    def test_empty_scan_results(self):
        """E1: Empty scan results must not crash."""
        dashboard = NagapashaDashboard()
        dashboard.scan_results = {}
        client = TestClient(dashboard.app)
        response = client.get("/api/status")
        assert response.status_code == 200

    def test_scan_results_with_missing_fields(self):
        """E1: Missing fields in scan results must not crash."""
        dashboard = NagapashaDashboard()
        dashboard.scan_results = {"total_endpoints": 10}
        client = TestClient(dashboard.app)
        response = client.get("/api/status")
        assert response.status_code == 200

    def test_multiple_updates(self):
        """E1: Multiple scan result updates must work."""
        dashboard = NagapashaDashboard()
        dashboard.update_scan({"total_endpoints": 5})
        dashboard.update_scan({"total_endpoints": 10, "total_findings": 2})
        client = TestClient(dashboard.app)
        response = client.get("/api/status")
        data = response.json()
        assert data["endpoints_found"] == 10
        assert data["findings_count"] == 2
