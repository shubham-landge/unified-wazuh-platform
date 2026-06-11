import pytest
import httpx
import json
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_health_endpoint():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/health", headers={"X-API-Key": "soc-key-001"})
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert "status" in data
        assert "version" in data


@pytest.mark.asyncio
async def test_health_endpoint_no_auth():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/health")
        assert resp.status_code == 401
        data = resp.json()
        assert "detail" in data


@pytest.mark.asyncio
async def test_alerts_endpoint():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/alerts/recent", headers={"X-API-Key": "soc-key-001"})
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert data.get("status") in ("success", "error")


@pytest.mark.asyncio
async def test_cases_endpoint():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/cases", headers={"X-API-Key": "soc-key-001"})
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert data.get("status") in ("success", "error")


@pytest.mark.asyncio
async def test_assets_endpoint():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/assets", headers={"X-API-Key": "soc-key-001"})
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert data.get("status") in ("success", "error")


@pytest.mark.asyncio
async def test_vulnerabilities_endpoint():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/vulnerabilities", headers={"X-API-Key": "soc-key-001"})
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert data.get("status") in ("success", "error")


@pytest.mark.asyncio
async def test_audit_endpoint():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/audit", headers={"X-API-Key": "soc-key-001"})
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert data.get("status") in ("success", "error")


@pytest.mark.asyncio
async def test_model_status_endpoint():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/model/status", headers={"X-API-Key": "soc-key-001"})
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert "provider" in data


@pytest.mark.asyncio
async def test_wazuh_health_endpoint():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/wazuh/health", headers={"X-API-Key": "soc-key-001"})
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert "api_url" in data
        assert "indexer_url" in data


@pytest.mark.asyncio
async def test_rate_limit():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        for _ in range(5):
            resp = await client.get("/health", headers={"X-API-Key": "soc-rate-test"})
            assert resp.status_code in (200, 429)


@pytest.mark.asyncio
async def test_invalid_api_key():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/health", headers={"X-API-Key": "invalid-key-12345"})
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_missing_api_key():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        resp = await client.get("/health")
        assert resp.status_code == 401
