import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.auth_jwt import get_current_user_optional
from app.middleware.tenant_enforce import get_tenant_id
from app.routers import usage
from shared.auth import TokenData
from shared.models.tenant import Tenant


def _make_result(rows=None, scalar_val=None):
    result = MagicMock()
    result.scalars.return_value.all.return_value = rows or []
    result.scalars.return_value.first.return_value = rows[0] if rows else None
    if scalar_val is not None:
        result.scalar.return_value = scalar_val
    return result


def _make_db(execute_return=None):
    db = MagicMock()
    db.execute = AsyncMock(return_value=execute_return or _make_result([]))
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


TENANT_ID = str(uuid.uuid4())


@pytest.mark.asyncio
async def test_get_usage_limits_defaults():
    db = _make_db()
    app = FastAPI()
    app.include_router(usage.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_tenant_id] = lambda: TENANT_ID

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/usage/limits")

    assert resp.status_code == 200
    data = resp.json()
    assert data["limits"]["alerts_per_month"] == 100000
    assert data["limits"]["api_calls_per_month"] == 500000
    assert data["limits"]["storage_gb"] == 10


@pytest.mark.asyncio
async def test_get_usage_limits_with_tenant_overrides():
    tenant = MagicMock(spec=Tenant)
    tenant.config = {"limits": {"alerts_per_month": 5000, "storage_gb": 50}}

    db = _make_db(_make_result([tenant]))
    app = FastAPI()
    app.include_router(usage.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_tenant_id] = lambda: TENANT_ID

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/usage/limits")

    assert resp.status_code == 200
    data = resp.json()
    assert data["limits"]["alerts_per_month"] == 5000
    assert data["limits"]["api_calls_per_month"] == 500000
    assert data["limits"]["storage_gb"] == 50


@pytest.mark.asyncio
async def test_get_all_tenants_usage_requires_admin():
    db = _make_db()
    app = FastAPI()
    app.include_router(usage.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_current_user_optional] = lambda: None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/usage/all-tenants")

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_get_all_tenants_usage_as_admin():
    tenant1 = MagicMock(spec=Tenant)
    tenant1.id = uuid.uuid4()
    tenant1.name = "Tenant A"
    tenant1.slug = "tenant-a"
    tenant1.config = {}
    tenant1.is_active = True

    tenant2 = MagicMock(spec=Tenant)
    tenant2.id = uuid.uuid4()
    tenant2.name = "Tenant B"
    tenant2.slug = "tenant-b"
    tenant2.config = {}
    tenant2.is_active = True

    usage_row = MagicMock()
    usage_row.tenant_id = tenant1.id
    usage_row.alerts_count = 5
    usage_row.api_calls_count = 100
    usage_row.storage_mb = 50
    usage_row.ai_triage_count = 2
    usage_row.total_score = 10

    db = _make_db()

    async def mock_execute(stmt):
        stmt_str = str(stmt)
        if "tenant" in stmt_str.lower() and "usage" not in stmt_str.lower():
            return _make_result([tenant1, tenant2])
        return _make_result([usage_row])

    db.execute = AsyncMock(side_effect=mock_execute)

    app = FastAPI()
    app.include_router(usage.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_current_user_optional] = lambda: TokenData(
        user_id="admin", email="admin@test.com", role="admin", permissions=["admin:tenant"]
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/usage/all-tenants")

    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2
    tenant_names = [t["tenant_name"] for t in data["tenants"]]
    assert "Tenant A" in tenant_names
    assert "Tenant B" in tenant_names


@pytest.mark.asyncio
async def test_record_usage_event():
    db = _make_db()
    app = FastAPI()
    app.include_router(usage.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_tenant_id] = lambda: TENANT_ID

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/usage/record", json={
            "event_type": "api_call",
            "resource_id": "test-resource",
            "resource_type": "test",
        })

    assert resp.status_code == 201
    assert resp.json()["status"] == "success"
    assert db.add.called


@pytest.mark.asyncio
async def test_get_usage_summary():
    db = _make_db()
    app = FastAPI()
    app.include_router(usage.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_tenant_id] = lambda: TENANT_ID

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/usage/summary")

    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"]["alerts_count"] == 0
