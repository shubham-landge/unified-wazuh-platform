import os
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("SECRET_KEY", "test-secret-key")


@pytest.fixture
def maigret_app():
    from services.maigret.app.main import app
    return app


@pytest.mark.asyncio
async def test_health_reports_installed(maigret_app):
    with patch("services.maigret.app.main.shutil.which", return_value="/usr/bin/maigret"):
        async with AsyncClient(transport=ASGITransport(app=maigret_app), base_url="http://test") as client:
            response = await client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["connected"] is True
    assert data["service"] == "maigret"


@pytest.mark.asyncio
async def test_health_reports_missing(maigret_app):
    with patch("services.maigret.app.main.shutil.which", return_value=None):
        async with AsyncClient(transport=ASGITransport(app=maigret_app), base_url="http://test") as client:
            response = await client.get("/health")

    assert response.status_code == 200
    assert response.json()["connected"] is False


@pytest.mark.asyncio
async def test_lookup_requires_username(maigret_app):
    async with AsyncClient(transport=ASGITransport(app=maigret_app), base_url="http://test") as client:
        response = await client.post("/lookup", json={"username": ""})

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_lookup_returns_normalized_profiles(maigret_app):
    raw_output = {
        "alice": {
            "sites": {
                "GitHub": {
                    "status": {"status": "claimed"},
                    "url_user": "https://github.com/alice",
                    "username": "alice",
                },
                "Twitter": {
                    "status": {"status": "claimed"},
                    "url_user": "https://twitter.com/alice",
                    "username": "alice",
                },
                "UnknownSite": {
                    "status": {"status": "claimed"},
                    # missing url_user -> filtered out
                },
            }
        }
    }

    with patch("services.maigret.app.main._run_maigret", return_value=raw_output["alice"]):
        async with AsyncClient(transport=ASGITransport(app=maigret_app), base_url="http://test") as client:
            response = await client.post("/lookup", json={"username": "alice"})

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2
    sources = {item["source"] for item in data}
    assert sources == {"github", "twitter"}
    assert data[0]["profile_url"].startswith("https://")


@pytest.mark.asyncio
async def test_lookup_handles_empty_results(maigret_app):
    with patch("services.maigret.app.main._run_maigret", return_value={}):
        async with AsyncClient(transport=ASGITransport(app=maigret_app), base_url="http://test") as client:
            response = await client.post("/lookup", json={"username": "bob"})

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_lookup_returns_503_when_maigret_missing(maigret_app):
    with patch("services.maigret.app.main.shutil.which", return_value=None):
        async with AsyncClient(transport=ASGITransport(app=maigret_app), base_url="http://test") as client:
            response = await client.post("/lookup", json={"username": "alice"})

    assert response.status_code == 503
