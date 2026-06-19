"""Tenant-isolation regression tests for the alert detail endpoint.

After removing the nil-UUID fallback, GET /alerts/{id} must require a tenant
context and scope the query to that tenant. A request with no tenant context
is rejected with 400; a request whose tenant does not own the alert sees 404.
"""
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from app.routers import alerts

_TENANT = "11111111-1111-1111-1111-111111111111"


def _empty_db():
    db = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=result)
    return db


def _build_app(tenant_override):
    app = FastAPI()
    app.include_router(alerts.router)
    app.dependency_overrides[get_db] = lambda: _empty_db()
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_tenant_id] = tenant_override
    return app


@pytest.mark.asyncio
async def test_alert_detail_requires_tenant_context():
    app = _build_app(lambda: None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"/alerts/{uuid.uuid4()}")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_alert_detail_scopes_to_tenant_not_found():
    # DB returns no row (alert belongs to a different tenant) -> 404, not a leak.
    app = _build_app(lambda: _TENANT)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"/alerts/{uuid.uuid4()}")
    assert resp.status_code == 404
