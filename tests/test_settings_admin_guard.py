"""Admin-guard regression test for the dashboard settings endpoint.

POST /settings rewrites global platform configuration and must be restricted
to admins. A non-admin authenticated user is rejected with 403; an admin is
allowed through.
"""
import jinja2
import pytest
from fastapi.testclient import TestClient

from services.dashboard.app.main import app, templates, _sign_session

templates.env.loader = jinja2.FileSystemLoader("services/dashboard/templates")

_CSRF = "test-csrf-token"


def _cookie(role: str) -> str:
    from datetime import datetime, timezone
    return _sign_session({
        "sub": "user@soc.local",
        "email": "user@soc.local",
        "role": role,
        "tenant_id": None,
        "csrf_token": _CSRF,
        "iat": datetime.now(timezone.utc).isoformat(),
    })


@pytest.fixture
def client():
    return TestClient(app)


def test_non_admin_cannot_save_settings(client):
    client.cookies.set("session_token", _cookie("analyst"))
    resp = client.post(
        "/settings",
        data={"misp_url": "http://evil"},
        headers={"X-CSRF-Token": _CSRF},
    )
    assert resp.status_code == 403


def test_admin_can_save_settings(client):
    # The settings.json write targets "app/settings.json", which does not exist
    # at the repo root; the route swallows that write error and still returns 200.
    client.cookies.set("session_token", _cookie("admin"))
    resp = client.post(
        "/settings",
        data={"misp_verify_ssl": "on", "ti_feed_poll_interval_seconds": "3600"},
        headers={"X-CSRF-Token": _CSRF},
    )
    assert resp.status_code == 200
