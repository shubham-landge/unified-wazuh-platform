"""Tests for the Wazuh environment health API router."""
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.routers import wazuh_health
from shared.models.wazuh_health import WazuhHealthSnapshot


def _snapshot():
    return WazuhHealthSnapshot(
        manager_label="default",
        captured_at=datetime.now(timezone.utc),
        agents_active=10, agents_disconnected=2, agents_total=12,
        cluster_status="green", manager_all_running=True,
        indexer_status="green", overall_status="degraded",
        issues=[{"severity": "warning", "code": "agents_disconnected", "detail": "2/12"}],
    )


def _app(scalar):
    db = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = scalar
    result.scalars.return_value.all.return_value = [scalar] if scalar else []
    db.execute = AsyncMock(return_value=result)

    app = FastAPI()
    app.include_router(wazuh_health.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "k"
    return app


@pytest.mark.asyncio
async def test_environment_returns_latest_snapshot():
    app = _app(_snapshot())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/wazuh/environment")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["snapshot"]["overall_status"] == "degraded"
    assert body["snapshot"]["agents"]["disconnected"] == 2


@pytest.mark.asyncio
async def test_environment_no_data():
    app = _app(None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/wazuh/environment")
    assert resp.json()["status"] == "no_data"
