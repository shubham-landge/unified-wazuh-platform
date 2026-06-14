import sys
from pathlib import Path
import uuid
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("SECRET_KEY", "test-secret-key")

ROOT = Path(__file__).resolve().parents[1]
api_path = str(ROOT / "services" / "api")
if api_path not in sys.path:
    sys.path.insert(0, api_path)

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from shared.models.base import Base
from shared.models.osint import OsintTarget, OsintResult


def _empty_result():
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    result.scalar_one_or_none.return_value = None
    return result


@pytest.fixture
def osint_app():
    from app.routers import osint

    db = MagicMock()
    db.execute = AsyncMock(return_value=_empty_result())
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    app = FastAPI()
    app.include_router(osint.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "soc-key-001"
    app.dependency_overrides[get_tenant_id] = lambda: "00000000-0000-0000-0000-000000000001"
    return app


@pytest.mark.asyncio
async def test_maigret_lookup_username_returns_results():
    from shared.connectors.osint_maigret import MaigretConnector

    connector = MaigretConnector(maigret_url="http://maigret:8080")
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {
        "results": [
            {
                "source": "github",
                "profile_url": "https://github.com/alice",
                "name": "Alice",
                "location": "Remote",
            }
        ]
    }

    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=response)
        results = await connector.lookup_username("alice")

    assert len(results) == 1
    assert results[0]["source"] == "github"
    assert results[0]["profile_url"] == "https://github.com/alice"


@pytest.mark.asyncio
async def test_maigret_health_returns_connected():
    from shared.connectors.osint_maigret import MaigretConnector

    connector = MaigretConnector(maigret_url="http://maigret:8080")
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {"connected": True}

    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=response)
        health = await connector.health()

    assert health["connected"] is True
    assert health["success"] is True


@pytest.mark.asyncio
async def test_post_lookup_enqueues_target(osint_app):
    redis_client = MagicMock()
    redis_client.lpush = AsyncMock(return_value=1)

    async with AsyncClient(transport=ASGITransport(app=osint_app), base_url="http://test") as client:
        with patch("app.routers.osint.redis.from_url", return_value=redis_client), patch("httpx.AsyncClient"):
            response = await client.post(
                "/osint/lookup",
                headers={"X-API-Key": "soc-key-001"},
                json={"target_type": "username", "target_value": "alice"},
            )

    assert response.status_code == 202
    assert response.json()["target_id"]
    redis_client.lpush.assert_awaited_once()


@pytest.mark.asyncio
async def test_osint_model_attributes_exist():
    target = OsintTarget(
        tenant_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        target_type="email",
        target_value="alice@example.com",
    )
    result = OsintResult(
        target_id=target.id,
        source="github",
        profile_url="https://github.com/alice",
        name="Alice",
        location="Remote",
        raw_data={"source": "github"},
    )

    assert target.target_type == "email"
    assert result.source == "github"
    assert "osint_targets" in Base.metadata.tables
    assert "osint_results" in Base.metadata.tables
