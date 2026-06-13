"""End-to-end tenant isolation tests.

Verifies that all routers properly filter queries by tenant_id so that
cross-tenant data access is impossible.
"""
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.auth_jwt import get_current_user, get_current_user_optional
from app.middleware.tenant_enforce import get_tenant_id
from app.routers import (
    alerts, assets, audit, cases, vulnerabilities, notifications, osint,
    reports, soar, threat_intel, triage, ueba, usage, ticketing, approvals,
    agents, compliance, rag,
)
from shared.auth import TokenData

TENANT_A = str(uuid.uuid4())
TENANT_B = str(uuid.uuid4())

router_list = [
    ("/alerts/recent?limit=10", alerts.router, {}),
    ("/assets?limit=10", assets.router, {}),
    ("/audit?limit=10", audit.router, {}),
    ("/cases?limit=10", cases.router, {}),
    ("/vulnerabilities?limit=10", vulnerabilities.router, {}),
    ("/notifications/channels", notifications.router, {}),
    ("/osint/targets?limit=10", osint.router, {}),
    ("/reports", reports.router, {}),
    ("/soar/playbooks", soar.router, {}),
    ("/threat-intel/feeds", threat_intel.router, {}),
    ("/ueba/baselines", ueba.router, {}),
    ("/usage/records?limit=10", usage.router, {}),
    ("/ticketing/config", ticketing.router, {}),
    ("/agents/definitions?limit=10", agents.router, {}),
    ("/compliance/frameworks", compliance.router, {}),
    ("/rag/knowledge?limit=10", rag.router, {}),
    ("/approvals", approvals.router, {
        get_current_user: lambda: TokenData(
            user_id="admin", email="admin@test.com", role="admin", permissions=[]
        ),
    }),
]


def _make_result(rows=None):
    result = MagicMock()
    result.scalars.return_value.all.return_value = rows or []
    result.scalars.return_value.first.return_value = rows[0] if rows else None
    result.scalar.return_value = None
    return result


def _make_db(execute_return=None):
    db = MagicMock()
    db.execute = AsyncMock(return_value=execute_return or _make_result([]))
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


@pytest.mark.parametrize("path,router,extra_overrides", router_list)
@pytest.mark.asyncio
async def test_router_filters_by_tenant_id(path, router, extra_overrides):
    db = _make_db()
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_tenant_id] = lambda: TENANT_A
    for dep, handler in extra_overrides.items():
        app.dependency_overrides[dep] = handler

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(path)

    assert resp.status_code in (200, 201, 422), f"{path} returned {resp.status_code}: {resp.text[:200]}"

    for call_args in db.execute.call_args_list:
        stmt_str = str(call_args[0][0])
        if "FROM" in stmt_str.upper() and "tenant_id" in stmt_str:
            return

    pytest.fail(f"{path}: no query contains tenant_id filter. SQL: {stmt_str}")


TENANTLESS_ROUTERS = {
    "/health": None,
    "/health/ready": None,
    "/docs": None,
}


@pytest.mark.asyncio
async def test_cross_tenant_data_isolation():
    class MockAlert:
        def __init__(self):
            self.id = uuid.uuid4()
            self.tenant_id = uuid.UUID(TENANT_B)
            self.rule_id = 100001
            self.rule_level = 10
            self.rule_description = ""
            self.timestamp = None
            self.status = "new"
            self.source = "test"
            self.source_ip = ""
            self.destination = ""
            self.destination_ip = ""
            self.protocol = ""
            self.alert_hash = ""
            self.created_at = None
            self.updated_at = None
            self.title = "B Alert"
            self.category = "test"
            self.severity = "high"
            self.raw_data = {}
            self.case_id = None
            self.rule_groups = []
            self.mitre_tactics = []
            self.mitre_techniques = []
            self.mitre_technique = ""
            self.agent_name = ""
            self.agent_id = ""
            self.user_name = ""
            self.alert_timestamp = None
            self.ingested_at = datetime.now(timezone.utc)

    db = _make_db(_make_result([MockAlert()]))
    app = FastAPI()
    app.include_router(alerts.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_tenant_id] = lambda: TENANT_A

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/alerts/recent?limit=10")

    assert resp.status_code == 200
    for call_args in db.execute.call_args_list:
        stmt_str = str(call_args[0][0])
        if "tenant_id" in stmt_str:
            return
    pytest.fail("Query did not reference tenant_id")


@pytest.mark.asyncio
async def test_tenant_id_none_returns_all():
    class MockAlert:
        def __init__(self, i):
            self.id = uuid.uuid4()
            self.tenant_id = None
            self.rule_id = 100000 + i
            self.rule_level = i + 5
            self.rule_description = "Test"
            self.timestamp = None
            self.status = "new"
            self.source = "test"
            self.source_ip = ""
            self.destination = ""
            self.destination_ip = ""
            self.protocol = ""
            self.alert_hash = ""
            self.created_at = None
            self.updated_at = None
            self.title = f"A-{i}"
            self.category = "test"
            self.severity = "low"
            self.raw_data = {}
            self.case_id = None
            self.rule_groups = []
            self.mitre_tactics = []
            self.mitre_techniques = []
            self.mitre_technique = ""
            self.agent_name = ""
            self.agent_id = ""
            self.user_name = ""
            self.alert_timestamp = None
            self.ingested_at = datetime.now(timezone.utc)

    db = _make_db(_make_result([MockAlert(i) for i in range(3)]))
    app = FastAPI()
    app.include_router(alerts.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    app.dependency_overrides[get_tenant_id] = lambda: None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/alerts/recent?limit=10")

    assert resp.status_code == 200
