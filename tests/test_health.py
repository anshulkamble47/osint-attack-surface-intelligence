"""Integration tests for Stage 0 Health and Readiness endpoints."""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Verify that the root endpoint returns platform information."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "platform" in data
    assert "version" in data
    assert data["status"] == "online"
    assert data["health_endpoint"] == "/api/health"


def test_health_endpoint_structure():
    """Verify that /api/health returns the expected schema."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()

    # Required top-level fields
    assert "status" in data
    assert data["status"] in ["ok", "degraded"]
    assert "service" in data
    assert "version" in data
    assert "environment" in data
    assert "timestamp" in data
    assert "database" in data

    # Required database fields
    db = data["database"]
    assert "connected" in db
    assert isinstance(db["connected"], bool)
    assert "dialect" in db
    assert "latency_ms" in db
    assert isinstance(db["latency_ms"], (int, float))


def test_dedicated_db_health_endpoint():
    """Verify that /api/health/db returns database-specific diagnostics."""
    response = client.get("/api/health/db")
    assert response.status_code == 200
    db = response.json()
    assert "connected" in db
    assert isinstance(db["connected"], bool)
    assert "dialect" in db
    assert "latency_ms" in db
