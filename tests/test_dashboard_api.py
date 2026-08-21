"""Tests for the dashboard REST API."""

import pytest
from fastapi.testclient import TestClient

from dashboard.app import app


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


def test_index(client):
    """Test the root endpoint returns HTML."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "nagapasha" in response.text.lower()


def test_list_engagements_empty(client):
    """Test listing engagements when none exist."""
    response = client.get("/api/engagements")
    assert response.status_code == 200
    assert response.json() == []


def test_create_engagement(client):
    """Test creating a new engagement."""
    response = client.post(
        "/api/engagements",
        json={
            "target_host": "https://example.com",
            "target_url": "https://example.com/api",
            "method": "GET",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "engagement_id" in data
    assert len(data["engagement_id"]) == 8


def test_get_engagement_not_found(client):
    """Test getting a nonexistent engagement."""
    response = client.get("/api/engagements/nonexistent")
    assert response.status_code == 200
    data = response.json()
    assert "error" in data


def test_create_and_get_engagement(client):
    """Test creating and then getting an engagement."""
    # Create
    create_response = client.post(
        "/api/engagements",
        json={
            "target_host": "https://example.com",
            "target_url": "https://example.com/api",
        },
    )
    engagement_id = create_response.json()["engagement_id"]

    # Get
    response = client.get(f"/api/engagements/{engagement_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == engagement_id
    assert data["target_host"] == "https://example.com"


def test_list_findings_empty(client):
    """Test listing findings when none exist."""
    response = client.get("/api/engagements/test1234/findings")
    assert response.status_code == 200
    assert response.json() == []


def test_get_live_status_not_found(client):
    """Test getting live status for a nonexistent run."""
    response = client.get("/api/live/nonexistent")
    assert response.status_code == 200
    data = response.json()
    assert "error" in data
