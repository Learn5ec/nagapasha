"""Tests for the WebSocket endpoint."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch

from dashboard.app import app
from dashboard import active_runs


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


def test_websocket_connect_and_disconnect(client):
    """Test connecting and disconnecting from WebSocket."""
    with client.websocket_connect("/ws/test1234") as websocket:
        # Should receive initial status (empty since no run)
        data = websocket.receive_json()
        assert data["type"] == "status"
        assert data["data"]["engagement_id"] == "test1234"


def test_websocket_pause_action(client):
    """Test sending a pause action."""
    from dashboard.runs import ActiveRun

    # Create a mock run
    mock_loop = MagicMock()
    mock_loop.pause.return_value = True
    mock_run = ActiveRun(engagement_id="test1234", status="running", loop=mock_loop)
    active_runs.start(mock_run)

    try:
        with client.websocket_connect("/ws/test1234") as websocket:
            # Receive initial status
            data = websocket.receive_json()
            assert data["type"] == "status"

            # Send pause action
            websocket.send_json({"action": "pause"})

            # Should receive action result
            result = websocket.receive_json()
            assert result["type"] == "action_result"
            assert result["action"] == "pause"
            assert result["success"] is True
    finally:
        # Clean up
        active_runs.remove("test1234")


def test_websocket_kill_action(client):
    """Test sending a kill action."""
    from dashboard.runs import ActiveRun

    # Create a mock run
    mock_loop = MagicMock()
    mock_loop.kill.return_value = None
    mock_run = ActiveRun(engagement_id="test1234", status="running", loop=mock_loop)
    active_runs.start(mock_run)

    try:
        with client.websocket_connect("/ws/test1234") as websocket:
            # Receive initial status
            data = websocket.receive_json()
            assert data["type"] == "status"

            # Send kill action
            websocket.send_json({"action": "kill"})

            # Should receive action result
            result = websocket.receive_json()
            assert result["type"] == "action_result"
            assert result["action"] == "kill"
            assert result["success"] is True
    finally:
        # Clean up
        active_runs.remove("test1234")


def test_websocket_invalid_json(client):
    """Test sending invalid JSON."""
    with client.websocket_connect("/ws/test1234") as websocket:
        # Receive initial status
        data = websocket.receive_json()
        assert data["type"] == "status"

        # Send invalid JSON
        websocket.send_text("not valid json")

        # Should receive error
        error = websocket.receive_json()
        assert error["type"] == "error"
        assert "Invalid JSON" in error["message"]


def test_websocket_no_action(client):
    """Test sending a message with no action."""
    with client.websocket_connect("/ws/test1234") as websocket:
        # Receive initial status
        data = websocket.receive_json()
        assert data["type"] == "status"

        # Send message without action
        websocket.send_json({"something": "else"})

        # Should not receive anything (silently ignored)
        # (In a real test, we'd set a timeout and verify no message)
