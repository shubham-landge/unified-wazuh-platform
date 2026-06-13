"""Tests for the dashboard branding/white-label feature."""
import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
import jinja2
from services.dashboard.app.main import app, templates

templates.env.loader = jinja2.FileSystemLoader("services/dashboard/templates")


@pytest.fixture
def client():
    return TestClient(app)


@patch("services.dashboard.app.main._get_branding")
@patch("services.dashboard.app.main.api_request")
def test_branding_settings_tab_returns_content(mock_api, mock_branding, client):
    mock_branding.return_value = {
        "primary_color": "#ff0000",
        "secondary_color": "#00ff00",
        "company_name": "TestCorp",
        "logo_url": "https://example.com/logo.png",
        "favicon_url": "",
        "custom_css": "body { background: red; }",
    }
    mock_api.return_value = {"status": "success"}

    client.cookies.set("session_token", "admin@company.com")
    resp = client.get("/settings/branding")

    assert resp.status_code == 200
    assert "White-Label Branding" in resp.text
    assert "#ff0000" in resp.text
    assert "TestCorp" in resp.text


@patch("services.dashboard.app.main._save_branding")
@patch("services.dashboard.app.main.api_request")
def test_save_branding_settings(mock_api, mock_save, client):
    mock_api.return_value = {"status": "success"}

    client.cookies.set("session_token", "admin@company.com")
    resp = client.post("/settings/branding", data={
        "primary_color": "#ff0000",
        "secondary_color": "#00ff00",
        "company_name": "MyOrg",
        "logo_url": "https://myorg.com/logo.png",
        "favicon_url": "",
        "custom_css": "",
    })

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["branding"]["primary_color"] == "#ff0000"
    assert data["branding"]["company_name"] == "MyOrg"


@patch("services.dashboard.app.main._get_branding")
@patch("services.dashboard.app.main.api_request")
def test_branding_appears_in_base_template(mock_api, mock_branding, client):
    mock_branding.return_value = {
        "primary_color": "#ff0000",
        "secondary_color": "#00ff00",
        "company_name": "BrandCorp",
        "logo_url": "",
        "favicon_url": "",
        "custom_css": "",
    }
    mock_api.side_effect = lambda method, path, *args, **kwargs: {
        "/health": {"status": "healthy"},
        "/alerts/recent?limit=100": {"alerts": []},
        "/cases?limit=100": {"cases": []},
        "/vulnerabilities?limit=100": {"vulnerabilities": []},
    }.get(path, {})

    client.cookies.set("session_token", "admin@company.com")
    resp = client.get("/")

    assert resp.status_code == 200
    assert "BRANDCORP" in resp.text
    assert "#ff0000" in resp.text


@patch("services.dashboard.app.main.api_request")
def test_branding_settings_tab_in_settings_page(mock_api, client):
    mock_api.return_value = {"status": "success"}
    client.cookies.set("session_token", "admin@company.com")
    resp = client.get("/settings")

    assert resp.status_code == 200
    assert "Branding" in resp.text
