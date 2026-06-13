from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.db import get_db
from app.routers import alerts, assets, audit, cases, health, vulnerabilities
from shared.connectors.llm_provider import OllamaProvider


def _empty_result():
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    result.scalar.return_value = 1
    return result


@pytest.fixture
def api_app():
    db = MagicMock()
    db.execute = AsyncMock(return_value=_empty_result())
    app = FastAPI()
    for router in (
        health.router,
        alerts.router,
        cases.router,
        assets.router,
        vulnerabilities.router,
        audit.router,
    ):
        app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db
    return app


@pytest.fixture
async def client(api_app):
    async with AsyncClient(
        transport=ASGITransport(app=api_app),
        base_url="http://test",
    ) as test_client:
        yield test_client


@pytest.mark.asyncio
async def test_health_endpoint(client):
    response = await client.get("/health", headers={"X-API-Key": "soc-test-key-001"})
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert "version" in response.json()


@pytest.mark.asyncio
async def test_health_endpoint_no_auth(client):
    response = await client.get("/health")
    assert response.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    ["/alerts/recent", "/cases", "/assets", "/vulnerabilities", "/audit"],
)
async def test_list_endpoints(client, path):
    response = await client.get(path, headers={"X-API-Key": "soc-test-key-001"})
    assert response.status_code == 200
    assert response.json()["status"] == "success"


@pytest.mark.asyncio
async def test_model_status_endpoint(client):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("services.api.app.routers.health.get_provider", lambda: OllamaProvider())
        mp.setattr(OllamaProvider, "health", AsyncMock(return_value={"connected": True}))
        response = await client.get(
            "/model/status", headers={"X-API-Key": "soc-test-key-001"}
        )
    assert response.status_code == 200
    assert "provider" in response.json()


@pytest.mark.asyncio
async def test_wazuh_health_endpoint(client):
    from unittest.mock import patch

    with patch("services.api.app.routers.health.WazuhAPIConnector.health", AsyncMock(return_value={"connected": True})), patch("services.api.app.routers.health.WazuhIndexerConnector.health", AsyncMock(return_value={"connected": True})):
        response = await client.get(
            "/wazuh/health", headers={"X-API-Key": "soc-test-key-001"}
        )
    assert response.status_code == 200
    assert "api_url" in response.json()
    assert "indexer_url" in response.json()


@pytest.mark.asyncio
async def test_repeated_requests(client):
    for _ in range(5):
        response = await client.get(
            "/health", headers={"X-API-Key": "soc-test-key-001"}
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_invalid_api_key(client):
    response = await client.get(
        "/alerts/recent", headers={"X-API-Key": "invalid-key-12345"}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_missing_api_key(client):
    response = await client.get("/alerts/recent")
    assert response.status_code == 401
