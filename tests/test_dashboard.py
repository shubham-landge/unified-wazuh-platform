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
    mock_api.side_effect = lambda method, path, *args, **kwargs: {
        "/wazuh/health": {
            "api_url": "https://wazuh.local:55000",
            "api_connected": True,
            "indexer_url": "https://indexer.local:9200",
            "indexer_connected": True,
        },
        "/model/status": {
            "provider": "ollama",
            "model": "qwen2.5-coder",
            "fast_model": "qwen2.5-coder:1.5b",
        },
        "/health": {
            "status": "healthy",
            "database": {"connected": True, "latency_ms": 4},
        },
        "/health/full": {
            "status": "healthy",
            "services": {
                "otx": {"connected": True, "username": "test_otx_user"},
                "misp": {"connected": True, "version": "2.4.150"},
                "virustotal": {"connected": True}
            }
        }
    }.get(path, {})

    resp = client.get("/health")
    assert resp.status_code == 200
    assert "System Integration Health" in resp.text
    assert "AlienVault OTX" in resp.text
    assert "MISP Platform" in resp.text
    assert "VirusTotal" in resp.text

@patch("services.dashboard.app.main.api_request")
def test_dashboard_health_status_partial(mock_api, client):
    mock_api.side_effect = lambda method, path, *args, **kwargs: {
        "/wazuh/health": {
            "api_url": "https://wazuh.local:55000",
            "api_connected": True,
            "indexer_url": "https://indexer.local:9200",
            "indexer_connected": True,
        },
        "/model/status": {
            "provider": "ollama",
            "model": "qwen2.5-coder",
            "fast_model": "qwen2.5-coder:1.5b",
        },
        "/health": {
            "status": "healthy",
            "database": {"connected": True, "latency_ms": 4},
        },
        "/health/full": {
            "status": "healthy",
            "services": {
                "otx": {"connected": True, "username": "test_otx_user"},
                "misp": {"connected": True, "version": "2.4.150"},
                "virustotal": {"connected": True}
            }
        }
    }.get(path, {})

    resp = client.get("/health/status")
    assert resp.status_code == 200
    assert "health-status-grid" in resp.text
    assert "AlienVault OTX" in resp.text
    assert "MISP Platform" in resp.text
    assert "VirusTotal" in resp.text

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

def test_dashboard_settings_page_ti(client):
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "Threat Intelligence Connectors" in resp.text
    assert "otx_api_key" in resp.text

def test_dashboard_settings_save_ti(client):
    data = {
        "otx_api_key": "some_otx_key",
        "misp_url": "https://misp.local",
        "misp_api_key": "some_misp_key",
        "misp_verify_ssl": "on",
        "virustotal_api_key": "some_vt_key",
        "ti_feed_poll_interval_seconds": "1800"
    }
    resp = client.post("/settings", data=data)
    assert resp.status_code == 200
    assert "Settings updated successfully" in resp.text

@patch("shared.connectors.ti_alienvault.AlienVaultOTXConnector.health")
def test_dashboard_test_connector_otx(mock_health, client):
    mock_health.return_value = {"connected": True, "username": "mock_otx_user"}
    resp = client.post("/settings/test-connector/otx", data={"otx_api_key": "testkey"})
    assert resp.status_code == 200
    assert "Connection successful" in resp.json()["html"]
    assert "mock_otx_user" in resp.json()["html"]

# --- Phase 3A: Authentication & Report Scheduler UI Tests ---

def test_login_page_renders(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "Wazuh AI SOC Platform" in resp.text
    assert "Email Address" in resp.text

def test_profile_page_requires_auth(client):
    resp = client.get("/profile", follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]

def test_profile_page_renders_with_auth(client):
    client.cookies.set("session_token", "analyst@company.com")
    resp = client.get("/profile")
    assert resp.status_code == 200
    assert "User Profile Settings" in resp.text
    assert "analyst@company.com" in resp.text

def test_users_page_admin_only(client):
    # Test unauthenticated redirect
    resp = client.get("/users", follow_redirects=False)
    assert resp.status_code == 303
    
    # Test analyst user redirect (forbidden/redirect)
    client.cookies.set("session_token", "analyst@company.com")
    resp = client.get("/users", follow_redirects=False)
    assert resp.status_code == 303
    
    # Test admin user renders
    client.cookies.set("session_token", "admin@company.com")
    resp = client.get("/users")
    assert resp.status_code == 200
    assert "Platform User Directory" in resp.text
    assert "Provision User Account" in resp.text

def test_report_schedules_page_loads(client):
    client.cookies.set("session_token", "admin@company.com")
    resp = client.get("/reports")
    assert resp.status_code == 200
    assert "Scheduled Reports" in resp.text
    assert "New Report Schedule" in resp.text

def test_create_schedule_submits_correctly(client):
    client.cookies.set("session_token", "admin@company.com")
    data = {
        "report_type": "vulnerability",
        "frequency": "daily",
        "email_to": "admin@company.com",
        "is_active": "on"
    }
    resp = client.post("/reports/schedules", data=data, follow_redirects=False)
    assert resp.status_code == 303
    assert "/reports" in resp.headers["location"]
