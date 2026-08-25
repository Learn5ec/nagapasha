"""Dashboard — Web interface for nagapasha.

Provides:
  - REST API for scan results
  - Endpoint browser
  - Findings viewer
  - Session management
  - Real-time updates (optional)

Framework: FastAPI (lightweight, async, auto-docs)
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Any, Optional, List
from datetime import datetime
import uvicorn


# ---------------------------------------------------------------------------
# Pydantic models for API
# ---------------------------------------------------------------------------


class EndpointSummary(BaseModel):
    """Summary of a discovered endpoint."""
    method: str
    path_template: str
    concrete_path: str
    risk_tags: List[str]
    parameter_count: int


class FindingSummary(BaseModel):
    """Summary of a security finding."""
    type: str
    severity: str  # low, medium, high, critical
    confidence: float
    endpoint: str
    description: str
    evidence: Optional[dict[str, Any]] = None


class SessionSummary(BaseModel):
    """Summary of a captured session."""
    label: str
    session_id: str
    expires_at: Optional[datetime] = None
    cookies: List[str] = []
    auth_header: Optional[str] = None


class ScanStatus(BaseModel):
    """Current scan status."""
    is_running: bool
    endpoints_found: int = 0
    endpoints_scanned: int = 0
    findings_count: int = 0
    sessions_count: int = 0
    bola_checks: int = 0
    errors: List[str] = []


class DashboardData(BaseModel):
    """Complete dashboard data payload."""
    scan_status: ScanStatus
    endpoints: List[EndpointSummary]
    findings: List[FindingSummary]
    sessions: List[SessionSummary]
    spec_urls: List[str]
    scan_duration_seconds: Optional[float] = None


# ---------------------------------------------------------------------------
# Dashboard app
# ---------------------------------------------------------------------------


class NagapashaDashboard:
    """Web dashboard for nagapasha.

    Attributes:
        app: FastAPI application instance
        scan_results: Latest scan results (updated by orchestrator)
    """

    def __init__(self):
        self.app = FastAPI(
            title="nagapasha Dashboard",
            description="Web interface for nagapasha DAST scanner",
            version="1.0.0",
        )
        self.scan_results: Optional[dict[str, Any]] = None
        self._setup_routes()

    def _setup_routes(self):
        """Setup API routes."""

        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard_index():
            """Main dashboard page."""
            return self._render_html()

        @self.app.get("/api/status", response_model=ScanStatus)
        async def get_status():
            """Get current scan status."""
            if not self.scan_results:
                return ScanStatus(is_running=False)

            results = self.scan_results
            return ScanStatus(
                is_running=results.get("is_running", False),
                endpoints_found=results.get("total_endpoints", 0),
                endpoints_scanned=results.get("endpoints_scanned", 0),
                findings_count=results.get("total_findings", 0),
                sessions_count=results.get("total_sessions", 0),
                bola_checks=results.get("total_bola_checks", 0),
                errors=results.get("total_errors", []),
            )

        @self.app.get("/api/endpoints", response_model=List[EndpointSummary])
        async def get_endpoints():
            """Get discovered endpoints."""
            if not self.scan_results:
                return []

            endpoints = self.scan_results.get("endpoints", [])
            result = []
            for ep in endpoints:
                # Handle both dict and object endpoints
                if isinstance(ep, dict):
                    result.append(EndpointSummary(
                        method=ep.get("method", ""),
                        path_template=ep.get("path_template", ""),
                        concrete_path=ep.get("concrete_path", ""),
                        risk_tags=ep.get("risk_tags", []),
                        parameter_count=len(ep.get("parameters", [])),
                    ))
                else:
                    result.append(EndpointSummary(
                        method=ep.method,
                        path_template=ep.path_template,
                        concrete_path=ep.concrete_path,
                        risk_tags=ep.risk_tags,
                        parameter_count=len(ep.parameters),
                    ))
            return result

        @self.app.get("/api/findings", response_model=List[FindingSummary])
        async def get_findings():
            """Get security findings."""
            if not self.scan_results:
                return []

            return [
                FindingSummary(
                    type=f.get("type", "unknown") if isinstance(f, dict) else getattr(f, "type", "unknown"),
                    severity=f.get("severity", "medium") if isinstance(f, dict) else getattr(f, "severity", "medium"),
                    confidence=f.get("confidence", 0.0) if isinstance(f, dict) else getattr(f, "confidence", 0.0),
                    endpoint=f.get("endpoint", "") if isinstance(f, dict) else getattr(f, "endpoint", ""),
                    description=f.get("description", "") if isinstance(f, dict) else getattr(f, "description", ""),
                    evidence=f.get("evidence") if isinstance(f, dict) else getattr(f, "evidence", None),
                )
                for f in self.scan_results.get("findings", [])
            ]

        @self.app.get("/api/sessions", response_model=List[SessionSummary])
        async def get_sessions():
            """Get captured sessions."""
            if not self.scan_results:
                return []

            sessions = self.scan_results.get("sessions", [])
            return [
                SessionSummary(
                    label=s.label if hasattr(s, "label") else s.get("label", ""),
                    session_id=s.session_id if hasattr(s, "session_id") else s.get("session_id", ""),
                    expires_at=s.expires_at if hasattr(s, "expires_at") else s.get("expires_at"),
                    cookies=list(s.cookies.keys()) if hasattr(s, "cookies") else list(s.get("cookies", {}).keys()),
                    auth_header=s.auth_header if hasattr(s, "auth_header") else s.get("auth_header"),
                )
                for s in sessions
            ]

        @self.app.put("/api/scan/update")
        async def update_scan(results: dict[str, Any]):
            """Update scan results (called by orchestrator)."""
            self.scan_results = results
            return {"status": "ok"}

    def update_scan(self, results: dict[str, Any]):
        """Update scan results directly (convenience method)."""
        self.scan_results = results

    def _render_html(self) -> str:
        """Render the main dashboard HTML."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>nagapasha Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: #161b22; border-bottom: 1px solid #30363d; padding: 20px 0; margin-bottom: 30px; }
        h1 { color: #58a6ff; font-size: 28px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
        .stat-value { font-size: 32px; font-weight: bold; color: #58a6ff; }
        .stat-label { color: #8b949e; font-size: 14px; margin-top: 5px; }
        .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .section h2 { color: #58a6ff; margin-bottom: 15px; font-size: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #30363d; }
        th { color: #8b949e; font-weight: 600; font-size: 12px; text-transform: uppercase; }
        .severity-high { color: #f85149; }
        .severity-medium { color: #d29922; }
        .severity-low { color: #7ee787; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; background: #30363d; }
        .badge-auth { background: #1f6feb33; color: #58a6ff; }
        .badge-write { background: #f8514933; color: #f85149; }
        .badge-delete { background: #da367333; color: #f778ba; }
        .loading { text-align: center; padding: 40px; color: #8b949e; }
        .error { color: #f85149; background: #f8514922; padding: 15px; border-radius: 6px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🛡️ nagapasha Dashboard</h1>
            <p style="color: #8b949e; margin-top: 10px;">Adaptive AI-Powered Intruder</p>
        </div>
    </header>

    <div class="container">
        <div id="error" class="error" style="display: none;"></div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" id="endpoints-count">-</div>
                <div class="stat-label">Endpoints Discovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="findings-count">-</div>
                <div class="stat-label">Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="sessions-count">-</div>
                <div class="stat-label">Sessions</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="bola-count">-</div>
                <div class="stat-label">BOLA Checks</div>
            </div>
        </div>

        <div class="section">
            <h2>Endpoints</h2>
            <div id="endpoints-list" class="loading">Loading...</div>
        </div>

        <div class="section">
            <h2>Findings</h2>
            <div id="findings-list" class="loading">Loading...</div>
        </div>

        <div class="section">
            <h2>Sessions</h2>
            <div id="sessions-list" class="loading">Loading...</div>
        </div>
    </div>

    <script>
        async function loadStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                document.getElementById('endpoints-count').textContent = data.endpoints_found;
                document.getElementById('findings-count').textContent = data.findings_count;
                document.getElementById('sessions-count').textContent = data.sessions_count;
                document.getElementById('bola-count').textContent = data.bola_checks;

                if (data.errors && data.errors.length > 0) {
                    const errorEl = document.getElementById('error');
                    errorEl.textContent = 'Errors: ' + data.errors.join(', ');
                    errorEl.style.display = 'block';
                }
            } catch (e) {
                console.error('Failed to load status:', e);
            }
        }

        async function loadEndpoints() {
            try {
                const response = await fetch('/api/endpoints');
                const data = await response.json();
                const container = document.getElementById('endpoints-list');

                if (data.length === 0) {
                    container.innerHTML = '<p style="color: #8b949e;">No endpoints discovered yet.</p>';
                    return;
                }

                container.innerHTML = '<table><thead><tr><th>Method</th><th>Path</th><th>Tags</th></tr></thead><tbody>' +
                    data.map(ep => `
                        <tr>
                            <td><strong>${ep.method}</strong></td>
                            <td><code>${ep.path_template}</code><br><small style="color: #8b949e;">${ep.concrete_path}</small></td>
                            <td>${ep.risk_tags.map(tag => `<span class="badge badge-${tag}">${tag}</span>`).join(' ')}</td>
                        </tr>
                    `).join('') + '</tbody></table>';
            } catch (e) {
                console.error('Failed to load endpoints:', e);
            }
        }

        async function loadFindings() {
            try {
                const response = await fetch('/api/findings');
                const data = await response.json();
                const container = document.getElementById('findings-list');

                if (data.length === 0) {
                    container.innerHTML = '<p style="color: #8b949e;">No findings detected.</p>';
                    return;
                }

                container.innerHTML = '<table><thead><tr><th>Type</th><th>Severity</th><th>Confidence</th><th>Endpoint</th></tr></thead><tbody>' +
                    data.map(f => `
                        <tr>
                            <td><strong>${f.type}</strong></td>
                            <td class="severity-${f.severity}">${f.severity.toUpperCase()}</td>
                            <td>${Math.round(f.confidence * 100)}%</td>
                            <td><code>${f.endpoint}</code></td>
                        </tr>
                    `).join('') + '</tbody></table>';
            } catch (e) {
                console.error('Failed to load findings:', e);
            }
        }

        async function loadSessions() {
            try {
                const response = await fetch('/api/sessions');
                const data = await response.json();
                const container = document.getElementById('sessions-list');

                if (data.length === 0) {
                    container.innerHTML = '<p style="color: #8b949e;">No sessions captured.</p>';
                    return;
                }

                container.innerHTML = '<table><thead><tr><th>Label</th><th>Session ID</th><th>Expires</th><th>Cookies</th></tr></thead><tbody>' +
                    data.map(s => `
                        <tr>
                            <td><strong>${s.label}</strong></td>
                            <td><code>${s.session_id}</code></td>
                            <td>${s.expires_at ? new Date(s.expires_at).toLocaleString() : 'Never'}</td>
                            <td>${s.cookies.length} cookie(s)</td>
                        </tr>
                    `).join('') + '</tbody></table>';
            } catch (e) {
                console.error('Failed to load sessions:', e);
            }
        }

        // Load data on page load
        loadStatus();
        loadEndpoints();
        loadFindings();
        loadSessions();

        // Refresh every 5 seconds
        setInterval(() => {
            loadStatus();
            loadEndpoints();
            loadFindings();
            loadSessions();
        }, 5000);
    </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_dashboard(host: str = "0.0.0.0", port: int = 8000) -> None:
    """Run the nagapasha dashboard.

    Args:
        host: Host to bind to
        port: Port to bind to
    """
    dashboard = NagapashaDashboard()

    # Mount static files (if any)
    # dashboard.app.mount("/static", StaticFiles(directory="static"), name="static")

    uvicorn.run(dashboard.app, host=host, port=port)


__all__ = ["NagapashaDashboard", "run_dashboard", "DashboardData"]
