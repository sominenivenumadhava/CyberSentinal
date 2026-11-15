"""
Unit tests for CyberSentinel FastAPI endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)


def test_health_endpoint():
    """Verify system health endpoint returns 200 and healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "CyberSentinel"


def test_root_endpoint():
    """Verify API root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert "CyberSentinel" in response.json()["message"]
