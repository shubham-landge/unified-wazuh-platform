"""Tests for the webhook/push ingestion endpoint (POST /alerts/event)."""

import hashlib
import hmac
import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.db import get_db
from app.routers import alerts_ingest
from shared.config import settings
from shared.models.alert import Alert


@pytest.fixture
def api_app():
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.add = MagicMock()
    db.flush = AsyncMock()

    app = FastAPI()
    app.include_router(alerts_ingest.router)
    app.dependency_overrides[get_db] = lambda: db
    return app


@pytest.fixture
async def client(api_app):
    async with AsyncClient(
        transport=ASGITransport(app=api_app),
        base_url="http://test",
    ) as test_client:
        yield test_client


# ── Helpers ──────────────────────────────────────────────────────────────────

GOOD_PAYLOAD = {
    "rule_id": 100001,
    "rule_description": "Test webhook alert",
    "source": "test_integrator",
    "rule_level": 10,
    "source_ip": "10.0.0.55",
    "user_name": "jdoe",
}


def _hmac_header(body: bytes, key: str = "soc-test-key-001") -> str:
    return hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def _mock_alert(alert_id: str | None = None) -> MagicMock:
    alert = MagicMock(spec=Alert)
    alert.id = uuid.UUID(alert_id) if alert_id else uuid.uuid4()
    return alert


# ── Tests ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ingest_success_api_key(client):
    """Valid API key + valid payload → 202 with alert_id."""
    mock_alert = _mock_alert()
    with (
        patch.object(
            alerts_ingest, "_get_poller"
        ) as mock_poller_factory,
        patch.object(
            alerts_ingest, "_get_redis", AsyncMock()
        ) as mock_redis,
        patch.object(
            settings, "webhook_ingest_enabled", True
        ),
    ):
        poller = MagicMock()
        poller._normalize_alert = AsyncMock(return_value=mock_alert)
        mock_poller_factory.return_value = poller

        response = await client.post(
            "/alerts/event",
            json=GOOD_PAYLOAD,
            headers={"X-API-Key": "soc-test-key-001"},
        )

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    assert uuid.UUID(data["alert_id"]) == mock_alert.id


@pytest.mark.asyncio
async def test_ingest_success_hmac(client):
    """Valid HMAC signature + valid payload → 202."""
    payload_bytes = json.dumps(GOOD_PAYLOAD).encode()
    sig = _hmac_header(payload_bytes)

    mock_alert = _mock_alert()
    with (
        patch.object(alerts_ingest, "_get_poller") as mock_poller_factory,
        patch.object(alerts_ingest, "_get_redis", AsyncMock()),
        patch.object(settings, "webhook_ingest_enabled", True),
    ):
        poller = MagicMock()
        poller._normalize_alert = AsyncMock(return_value=mock_alert)
        mock_poller_factory.return_value = poller

        response = await client.post(
            "/alerts/event",
            content=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "X-HMAC-Signature": sig,
            },
        )

    assert response.status_code == 202
    assert response.json()["status"] == "accepted"


@pytest.mark.asyncio
async def test_ingest_no_auth(client):
    """No auth headers → 401."""
    with patch.object(settings, "webhook_ingest_enabled", True):
        response = await client.post("/alerts/event", json=GOOD_PAYLOAD)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_ingest_invalid_api_key(client):
    """Invalid API key → 401."""
    with patch.object(settings, "webhook_ingest_enabled", True):
        response = await client.post(
            "/alerts/event",
            json=GOOD_PAYLOAD,
            headers={"X-API-Key": "bad-key"},
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_ingest_invalid_hmac(client):
    """Bad HMAC signature → 401."""
    with patch.object(settings, "webhook_ingest_enabled", True):
        response = await client.post(
            "/alerts/event",
            content=json.dumps(GOOD_PAYLOAD).encode(),
            headers={
                "Content-Type": "application/json",
                "X-HMAC-Signature": "deadbeef",
            },
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_ingest_malformed_payload(client):
    """Missing required fields → 422."""
    with patch.object(settings, "webhook_ingest_enabled", True):
        response = await client.post(
            "/alerts/event",
            json={"rule_id": 1},  # missing rule_description, source
            headers={"X-API-Key": "soc-test-key-001"},
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_ingest_disabled(client):
    """webhook_ingest_enabled=False → 404."""
    with patch.object(settings, "webhook_ingest_enabled", False):
        response = await client.post(
            "/alerts/event",
            json=GOOD_PAYLOAD,
            headers={"X-API-Key": "soc-test-key-001"},
        )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_ingest_with_source_path(client):
    """Path parameter overrides payload.source."""
    mock_alert = _mock_alert()
    with (
        patch.object(alerts_ingest, "_get_poller") as mock_poller_factory,
        patch.object(alerts_ingest, "_get_redis", AsyncMock()),
        patch.object(settings, "webhook_ingest_enabled", True),
    ):
        poller = MagicMock()
        poller._normalize_alert = AsyncMock(return_value=mock_alert)
        mock_poller_factory.return_value = poller

        response = await client.post(
            "/alerts/event/custom_source",
            json=GOOD_PAYLOAD,
            headers={"X-API-Key": "soc-test-key-001"},
        )

    assert response.status_code == 202
    # Verify manager_label passed to normalize was "custom_source", not "test_integrator"
    assert poller._normalize_alert.call_args[0][2] == "custom_source"
