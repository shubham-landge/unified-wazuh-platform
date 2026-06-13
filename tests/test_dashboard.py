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


@patch("services.dashboard.app.main.get_store")
def test_feedback_page_requires_admin(mock_get_store, client):
    # Mock return value of get_store
    mock_get_store.return_value = {
        "feedback": [
            {
                "triage_id": "test-triage-123",
                "rating": "not_helpful",
                "corrected_category": "malware",
                "corrected_severity": "high",
                "comments": "False positive test",
                "operator": "admin@company.com",
                "created_at": "2026-06-13T12:00:00"
            }
        ]
    }

    # Test unauthenticated redirect
    resp = client.get("/feedback", follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]
    
    # Test analyst user redirect (forbidden/redirect)
    client.cookies.set("session_token", "analyst@company.com")
    resp = client.get("/feedback", follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]
    
    # Test admin user renders feedback page
    client.cookies.set("session_token", "admin@company.com")
    resp = client.get("/feedback")
    assert resp.status_code == 200
    assert "AI Feedback Analytics Console" in resp.text
    assert "test-triage-123" in resp.text
    assert "False positive test" in resp.text


# --- Phase 4B: MTTR Dashboard + ATT&CK Heatmap tests ---

@patch("services.dashboard.app.main.api_request")
def test_mttr_dashboard_loads(mock_api, client):
    mock_api.side_effect = lambda method, path, *args, **kwargs: {
        "/cases/stats/mttr?days=30": {
            "status": "success",
            "total_cases": 78,
            "open": 14,
            "in_progress": 8,
            "resolved": 32,
            "closed": 18,
            "false_positive": 6,
            "avg_mttr_hours": 4.75,
            "closed_within_24h": 28,
            "closed_within_7d": 42,
            "total_resolved": 50,
            "trend": [
                {"date": "2026-06-01", "avg_hours": 5.2},
                {"date": "2026-06-02", "avg_hours": 4.8},
                {"date": "2026-06-03", "avg_hours": 4.1},
            ]
        },
        "/cases?limit=100": {
            "status": "success",
            "cases": [
                {"id": "c1", "status": "open", "severity": "critical"},
                {"id": "c2", "status": "resolved", "severity": "high"},
            ]
        },
        "/cases/stats/mitre-heatmap": {
            "status": "success",
            "tactics": ["TA0001", "TA0002"],
            "techniques_per_tactic": {
                "TA0001": [{"tactic": "TA0001", "technique": "T1078", "name": "Valid Accounts", "count": 5}],
                "TA0002": [{"tactic": "TA0002", "technique": "T1059", "name": "Command and Scripting Interpreter", "count": 3}]
            },
            "total_techniques": 8,
            "unique_techniques": 2
        }
    }

    client.cookies.set("session_token", "admin@company.com")
    resp = client.get("/mttr-dashboard")
    assert resp.status_code == 200
    assert "MTTR Analytics Dashboard" in resp.text
    assert "4.8" in resp.text  # avg_mttr_hours value appears
    assert "mttrTrendChart" in resp.text
    assert "caseStatusChart" in resp.text


@patch("services.dashboard.app.main.api_request")
def test_attack_heatmap_loads(mock_api, client):
    mock_api.side_effect = lambda method, path, *args, **kwargs: {
        "/cases/stats/mitre-heatmap": {
            "status": "success",
            "tactics": ["TA0001", "TA0002", "TA0003"],
            "techniques_per_tactic": {
                "TA0001": [{"tactic": "TA0001", "technique": "T1078", "name": "Valid Accounts", "count": 5}],
                "TA0002": [{"tactic": "TA0002", "technique": "T1059", "name": "Command and Scripting Interpreter", "count": 3}],
                "TA0003": [{"tactic": "TA0003", "technique": "T1505", "name": "Server Software Component", "count": 1}]
            },
            "total_techniques": 9,
            "unique_techniques": 3
        },
        "/cases?limit=100": {
            "status": "success",
            "cases": []
        }
    }

    client.cookies.set("session_token", "admin@company.com")
    resp = client.get("/attack-heatmap")
    assert resp.status_code == 200
    assert "ATT&CK Heatmap" in resp.text
    assert "attackHeatmapMatrix" in resp.text
    assert "T1078" in resp.text
    assert "T1059" in resp.text


@patch("services.dashboard.app.main.api_request")
def test_mttr_stats_api(mock_api, client):
    mock_api.return_value = {
        "status": "success",
        "total_cases": 10,
        "avg_mttr_hours": 3.5,
        "open": 3,
        "in_progress": 2,
        "resolved": 4,
        "closed": 1,
        "false_positive": 0,
        "closed_within_24h": 3,
        "closed_within_7d": 5,
        "total_resolved": 5,
        "trend": []
    }

    client.cookies.set("session_token", "admin@company.com")
    resp = client.get("/mttr-dashboard")
    assert resp.status_code == 200
    assert "3.5" in resp.text


# --- End Phase 4B tests ---


@patch("services.dashboard.app.main.save_store")
@patch("services.dashboard.app.main.get_store")
def test_submit_feedback(mock_get_store, mock_save_store, client):
    mock_get_store.return_value = {}
    
    client.cookies.set("session_token", "analyst@company.com")
    data = {
        "rating": "not_helpful",
        "corrected_category": "recon",
        "corrected_severity": "low",
        "comments": "Authorized port scan"
    }
    
    resp = client.post("/feedback/session-999", data=data)
    assert resp.status_code == 200
    assert resp.json() == {"status": "success"}
    
    # Verify save_store was called with the appended feedback
    mock_save_store.assert_called_once()
    saved_arg = mock_save_store.call_args[0][0]
    assert "feedback" in saved_arg
    assert len(saved_arg["feedback"]) == 1
    assert saved_arg["feedback"][0]["triage_id"] == "session-999"
    assert saved_arg["feedback"][0]["rating"] == "not_helpful"
    assert saved_arg["feedback"][0]["corrected_category"] == "recon"
    assert saved_arg["feedback"][0]["corrected_severity"] == "low"
    assert saved_arg["feedback"][0]["comments"] == "Authorized port scan"
    assert saved_arg["feedback"][0]["operator"] == "analyst@company.com"

