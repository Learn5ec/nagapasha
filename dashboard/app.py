"""FastAPI app for the nagapasha dashboard.

This module creates and configures the FastAPI application with:
- CORS middleware
- Static file serving
- WebSocket endpoint at /ws/{engagement_id}
- REST endpoints (delegated to api.py)
- CLI entry point via `uvicorn.run()`
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from uvicorn import Config, Server

from dashboard import active_runs, event_bus
from dashboard.api import router as api_router
from dashboard.live import websocket_endpoint


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="nagapasha",
        description="Adaptive AI-Powered Intruder — Dashboard",
        version="0.1.0",
    )

    # CORS — allow all origins during development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount REST API
    app.include_router(api_router, prefix="/api")

    # Mount WebSocket endpoint
    app.websocket("/ws/{engagement_id}")(websocket_endpoint)

    # Serve static files
    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Default route serves index.html
    @app.get("/")
    async def index():
        """Serve the dashboard UI."""
        from fastapi.responses import FileResponse
        static_dir = Path(__file__).parent / "static"
        return FileResponse(static_dir / "index.html")

    return app


# Module-scoped app instance
app = create_app()


def run_dashboard(host: str = "0.0.0.0", port: int = 8000) -> None:
    """Run the dashboard server via uvicorn."""
    config = Config(app=app, host=host, port=port, log_level="info")
    server = Server(config)
    server.run()


if __name__ == "__main__":
    run_dashboard()
