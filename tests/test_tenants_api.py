import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.auth_jwt import get_current_user_optional
from app.routers import tenants
from shared.auth import TokenData


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


@pytest.mark.asyncio
async def test_list_tenants_requires_admin():
    db = _make_db()
    app = FastAPI()
    app.include_router(tenants.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_current_user_optional] = lambda: None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/tenants")

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Super admin access required"


@pytest.mark.asyncio
async def test_list_tenants_as_admin():
    tenant = MagicMock()
    tenant.id = uuid.uuid4()
    tenant.name = "TestCorp"
    tenant.slug = "testcorp"
    tenant.config = {}
    tenant.is_active = True
    tenant.created_at = None
    tenant.updated_at = None

    db = _make_db(_make_result([tenant]))
    app = FastAPI()
    app.include_router(tenants.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_current_user_optional] = lambda: TokenData(
        user_id="admin", email="admin@test.com", role="admin", permissions=["admin:tenant"]
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/tenants")

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert len(data["tenants"]) == 1
    assert data["tenants"][0]["name"] == "TestCorp"


@pytest.mark.asyncio
async def test_create_tenant_duplicate_slug():
    existing = MagicMock()
    existing.slug = "testcorp"
    existing.name = "Existing"
    existing.id = uuid.uuid4()

    db = _make_db(_make_result([existing]))
    app = FastAPI()
    app.include_router(tenants.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_current_user_optional] = lambda: TokenData(
        user_id="admin", email="admin@test.com", role="admin", permissions=["admin:tenant"]
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/tenants", json={"name": "TestCorp", "slug": "testcorp"})

    assert resp.status_code == 409
    assert "slug already exists" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_update_tenant_branding():
    tenant = MagicMock()
    tenant.id = uuid.uuid4()
    tenant.name = "TestCorp"
    tenant.slug = "testcorp"
    tenant.config = {}
    tenant.is_active = True

    db = _make_db(_make_result([tenant]))
    app = FastAPI()
    app.include_router(tenants.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_current_user_optional] = lambda: TokenData(
        user_id="admin", email="admin@test.com", role="admin", permissions=["admin:tenant"]
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.patch(f"/tenants/{tenant.id}/branding", json={
            "primary_color": "#ff0000",
            "company_name": "MyCorp",
            "logo_url": "https://example.com/logo.png",
        })

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["branding"]["primary_color"] == "#ff0000"
    assert data["branding"]["company_name"] == "MyCorp"
    assert data["branding"]["logo_url"] == "https://example.com/logo.png"


@pytest.mark.asyncio
async def test_get_tenant_stats():
    tenant = MagicMock()
    tenant.id = uuid.uuid4()

    db = _make_db()
    db.execute = AsyncMock(return_value=MagicMock(scalar=MagicMock(return_value=42)))
    app = FastAPI()
    app.include_router(tenants.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_current_user_optional] = lambda: TokenData(
        user_id="admin", email="admin@test.com", role="admin", permissions=["admin:tenant"]
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(f"/tenants/{tenant.id}/stats")

    assert resp.status_code == 200
    data = resp.json()
    assert data["stats"]["alerts_count"] == 42
    assert data["stats"]["cases_count"] == 42
    assert data["stats"]["assets_count"] == 42
    assert data["stats"]["users_count"] == 42


@pytest.mark.asyncio
async def test_deactivate_tenant():
    tenant = MagicMock()
    tenant.id = uuid.uuid4()
    tenant.is_active = True
    tenant.updated_at = None

    db = _make_db(_make_result([tenant]))
    app = FastAPI()
    app.include_router(tenants.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_current_user_optional] = lambda: TokenData(
        user_id="admin", email="admin@test.com", role="admin", permissions=["admin:tenant"]
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.delete(f"/tenants/{tenant.id}")

    assert resp.status_code == 200
    assert resp.json()["message"] == "Tenant deactivated"
    assert tenant.is_active is False
