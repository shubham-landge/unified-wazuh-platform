from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from app.routers import notifications, soar, threat_intel, ueba

_TEST_TENANT = "11111111-1111-1111-1111-111111111111"


def _empty_result():
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    return result


@pytest.fixture
def domain_app():
    db = MagicMock()
    db.execute = AsyncMock(return_value=_empty_result())
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    db.refresh = AsyncMock()
    app = FastAPI()
    for router in (
        notifications.router,
        soar.router,
        threat_intel.router,
        ueba.router,
    ):
        app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "soc-key-001"
    app.dependency_overrides[get_tenant_id] = lambda: _TEST_TENANT
    return app


@pytest.mark.asyncio
async def test_new_domain_list_endpoints(domain_app):
    async with AsyncClient(
        transport=ASGITransport(app=domain_app),
        base_url="http://test",
    ) as client:
        for path in (
            "/notifications/channels",
            "/notifications/rules",
            "/notifications/events",
            "/soar/playbooks",
            "/soar/tasks",
            "/soar/executions",
            "/threat-intel/feeds",
            "/threat-intel/indicators",
            "/ueba/baselines",
            "/ueba/anomalies",
        ):
            response = await client.get(path)
            assert response.status_code == 200
            assert response.json()["status"] == "success"


@pytest.mark.asyncio
async def test_create_notification_channel(domain_app):
    async with AsyncClient(
        transport=ASGITransport(app=domain_app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/notifications/channels",
            json={
                "name": "Slack",
                "channel_type": "slack",
                "destination": "#soc",
            },
        )
    assert response.status_code == 201
    assert response.json()["channel"]["name"] == "Slack"


@pytest.mark.asyncio
async def test_create_soar_playbook(domain_app):
    async with AsyncClient(
        transport=ASGITransport(app=domain_app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/soar/playbooks",
            json={"name": "Containment", "trigger_type": "critical_alert"},
        )
    assert response.status_code == 201
    assert response.json()["playbook"]["name"] == "Containment"


@pytest.mark.asyncio
async def test_create_threat_feed_and_ueba_anomaly(domain_app):
    async with AsyncClient(
        transport=ASGITransport(app=domain_app),
        base_url="http://test",
    ) as client:
        feed = await client.post(
            "/threat-intel/feeds",
            json={
                "name": "MISP",
                "source_url": "https://misp.example/api",
                "feed_type": "misp",
            },
        )
        anomaly = await client.post(
            "/ueba/anomalies",
            json={
                "subject_type": "user",
                "subject_id": "alice",
                "anomaly_type": "login_spike",
                "score": 0.88,
            },
        )
    assert feed.status_code == 201
    assert anomaly.status_code == 201
    assert feed.json()["feed"]["name"] == "MISP"
    assert anomaly.json()["anomaly"]["subject_id"] == "alice"


@pytest.mark.asyncio
async def test_real_health_routes_are_mockable():
    from app.routers.health import router as health_router

    app = FastAPI()
    app.include_router(health_router)
    app.dependency_overrides[validate_api_key] = lambda: "soc-key-001"

    with patch("app.routers.health.WazuhAPIConnector.health", AsyncMock(return_value={"connected": True})), patch("app.routers.health.WazuhIndexerConnector.health", AsyncMock(return_value={"connected": True})), patch("app.routers.health.get_provider") as get_provider:
        provider = SimpleNamespace(name=lambda: "ollama/qwen", health=AsyncMock(return_value={"connected": True}), model="qwen")
        get_provider.return_value = provider
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            wazuh = await client.get("/wazuh/health")
            model = await client.get("/model/status")

    assert wazuh.status_code == 200
    assert model.status_code == 200
    assert model.json()["connected"] is True
