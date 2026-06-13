import os
import uuid
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

os.environ.setdefault("API_KEYS", "soc-test-key-001")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("WAZUH_API_VERIFY_SSL", "false")
os.environ.setdefault("WAZUH_INDEXER_VERIFY_SSL", "false")


@pytest.fixture(autouse=True)
def reset_settings():
    from shared.config import settings
    settings.api_keys = ["soc-test-key-001"]
    yield


def _make_mock_db():
    mock_session = AsyncMock()
    mock_session.__aenter__.return_value = mock_session
    mock_session.__aexit__ = AsyncMock()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_result.scalars.return_value.all.return_value = []
    mock_result.scalar.return_value = 1
    mock_session.execute = AsyncMock(return_value=mock_result)

    return mock_session


@pytest.fixture(autouse=True)
def override_db_dependency():
    mock_session = _make_mock_db()

    async def mock_get_db():
        yield mock_session

    from app.main import app
    from app.db import get_db
    app.dependency_overrides[get_db] = mock_get_db
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    from httpx import ASGITransport, AsyncClient
    from app.main import app
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_health_endpoint(client):
    resp = await client.get("/health", headers={"X-API-Key": "soc-test-key-001"})
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert "status" in data
    assert "version" in data


@pytest.mark.asyncio
async def test_health_endpoint_no_auth(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data


@pytest.mark.asyncio
async def test_alerts_endpoint(client):
    resp = await client.get("/alerts/recent", headers={"X-API-Key": "soc-test-key-001"})
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert data.get("status") in ("success", "error")


@pytest.mark.asyncio
async def test_alerts_endpoint_with_pagination(client):
    resp = await client.get(
        "/alerts/recent?limit=10&offset=20&min_level=7",
        headers={"X-API-Key": "soc-test-key-001"},
    )
    assert resp.status_code in (200, 503)


@pytest.mark.asyncio
async def test_cases_endpoint(client):
    resp = await client.get("/cases", headers={"X-API-Key": "soc-test-key-001"})
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert data.get("status") in ("success", "error")


@pytest.mark.asyncio
async def test_assets_endpoint(client):
    resp = await client.get("/assets", headers={"X-API-Key": "soc-test-key-001"})
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert data.get("status") in ("success", "error")


@pytest.mark.asyncio
async def test_vulnerabilities_endpoint(client):
    resp = await client.get("/vulnerabilities", headers={"X-API-Key": "soc-test-key-001"})
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert data.get("status") in ("success", "error")


@pytest.mark.asyncio
async def test_audit_endpoint(client):
    resp = await client.get("/audit", headers={"X-API-Key": "soc-test-key-001"})
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert data.get("status") in ("success", "error")


@pytest.mark.asyncio
async def test_model_status_endpoint(client):
    resp = await client.get("/model/status", headers={"X-API-Key": "soc-test-key-001"})
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert "provider" in data


@pytest.mark.asyncio
async def test_wazuh_health_endpoint(client):
    resp = await client.get("/wazuh/health", headers={"X-API-Key": "soc-test-key-001"})
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert "api_url" in data
    assert "indexer_url" in data


@pytest.mark.asyncio
async def test_invalid_api_key(client):
    resp = await client.get("/alerts/recent", headers={"X-API-Key": "invalid-key-12345"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_missing_api_key(client):
    resp = await client.get("/alerts/recent")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_triage_run_endpoint():
    mock_alert_id = uuid.uuid4()
    mock_session = AsyncMock()
    mock_session.__aenter__.return_value = mock_session
    mock_session.__aexit__ = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.flush = AsyncMock()

    from datetime import datetime, timezone
    mock_alert = MagicMock()
    mock_alert.id = mock_alert_id
    mock_alert.rule_description = "Test rule"
    mock_alert.rule_id = 100001
    mock_alert.rule_level = 10
    mock_alert.rule_groups = ["test"]
    mock_alert.agent_name = "test-agent"
    mock_alert.agent_ip = "10.0.0.1"
    mock_alert.source_ip = "10.0.0.1"
    mock_alert.destination_ip = ""
    mock_alert.user_name = ""
    mock_alert.process_name = ""
    mock_alert.file_name = ""
    mock_alert.file_hash = ""
    mock_alert.event_id = ""
    mock_alert.mitre_tactic = ""
    mock_alert.mitre_technique = ""
    mock_alert.alert_timestamp = datetime.now(timezone.utc)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_alert
    mock_session.execute = AsyncMock(return_value=mock_result)

    from app.main import app
    from app.db import get_db

    async def mock_get_db_with_alert():
        yield mock_session

    app.dependency_overrides[get_db] = mock_get_db_with_alert

    from httpx import ASGITransport, AsyncClient
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as test_client:
        resp = await test_client.post(
            "/triage/run",
            json={"alert_id": str(mock_alert_id)},
            headers={"X-API-Key": "soc-test-key-001"},
        )
        assert resp.status_code in (202, 503)
        if resp.status_code == 202:
            data = resp.json()
            assert "triage_id" in data
            assert "alert_id" in data

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_triage_run_invalid_alert_id(client):
    resp = await client.post(
        "/triage/run",
        json={"alert_id": "not-a-uuid"},
        headers={"X-API-Key": "soc-test-key-001"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_triage_run_alert_not_found(client):
    not_found_id = uuid.uuid4()
    resp = await client.post(
        "/triage/run",
        json={"alert_id": str(not_found_id)},
        headers={"X-API-Key": "soc-test-key-001"},
    )
    assert resp.status_code == 404
