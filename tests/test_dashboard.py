import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
import jinja2
from services.dashboard.app.main import app, templates

# Adjust templates directory loader for root-level test execution
templates.env.loader = jinja2.FileSystemLoader("services/dashboard/templates")

@pytest.fixture
def client():
    return TestClient(app)

@patch("services.dashboard.app.main.api_request")
def test_dashboard_health_page(mock_api, client):
    # Mock API health responses
    mock_api.return_value = {
        "status": "healthy",
        "database": {"connected": True, "latency_ms": 4},
        "api_url": "https://wazuh.local:55000",
        "api_connected": True,
        "indexer_url": "https://indexer.local:9200",
        "indexer_connected": True,
        "provider": "ollama",
        "model": "qwen2.5-coder",
        "fast_model": "qwen2.5-coder:1.5b"
    }
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "System Integration Health" in resp.text

@patch("services.dashboard.app.main.api_request")
def test_dashboard_health_status_partial(mock_api, client):
    mock_api.return_value = {
        "status": "healthy",
        "database": {"connected": True, "latency_ms": 4},
        "api_url": "https://wazuh.local:55000",
        "api_connected": True,
        "indexer_url": "https://indexer.local:9200",
        "indexer_connected": True,
        "provider": "ollama",
        "model": "qwen2.5-coder",
        "fast_model": "qwen2.5-coder:1.5b"
    }
    resp = client.get("/health/status")
    assert resp.status_code == 200
    assert "health-status-grid" in resp.text

@patch("services.dashboard.app.main.api_request")
def test_dashboard_compliance_page(mock_api, client):
    mock_api.return_value = {"alerts": [], "vulnerabilities": []}
    resp = client.get("/compliance")
    assert resp.status_code == 200
    assert "Compliance Mapping Console" in resp.text

def test_dashboard_notifications_page(client):
    resp = client.get("/notifications")
    assert resp.status_code == 200
    assert "Notification Center" in resp.text

def test_dashboard_playbooks_page(client):
    resp = client.get("/playbooks")
    assert resp.status_code == 200
    assert "SOC Automation Playbooks" in resp.text

def test_dashboard_threat_intel_page(client):
    resp = client.get("/threat-intel")
    assert resp.status_code == 200
    assert "Threat Intelligence" in resp.text

def test_dashboard_threat_intel_query(client):
    resp = client.get("/threat-intel?query=192.168.1.1")
    assert resp.status_code == 200
    assert "Threat Intelligence" in resp.text
    assert "Indicator Intel Profile" in resp.text
