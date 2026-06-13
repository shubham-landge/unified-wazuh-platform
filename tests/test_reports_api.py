import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.routers.reports import router


@pytest.mark.asyncio
async def test_list_reports_with_dependency_overrides():
    report = SimpleNamespace(
        id=uuid.uuid4(),
        name="Executive Report",
        report_type="executive",
        format="PDF",
        parameters={},
        file_size=128,
        status="completed",
        error_message=None,
        created_by="test",
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        expires_at=None,
    )
    result = MagicMock()
    result.scalars.return_value.all.return_value = [report]
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/reports")

    assert response.status_code == 200
    assert response.json()["reports"][0]["type"] == "executive"


@pytest.mark.asyncio
async def test_get_report_returns_404():
    db = MagicMock()
    db.get = AsyncMock(return_value=None)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "test-key"

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(f"/reports/{uuid.uuid4()}")

    assert response.status_code == 404
