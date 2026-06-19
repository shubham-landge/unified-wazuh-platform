"""Reaper test: a stale 'pending' triage is failed so the UI stops polling."""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.routers import triage


def _triage_row(created_at, status="pending"):
    row = MagicMock()
    row.id = uuid.uuid4()
    row.alert_id = uuid.uuid4()
    row.status = status
    row.created_at = created_at
    return row


def _app(row):
    db = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()

    app = FastAPI()
    app.include_router(triage.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[validate_api_key] = lambda: "k"
    return app, db


@pytest.mark.asyncio
async def test_stale_pending_is_reaped_to_failed():
    old = datetime.now(timezone.utc) - timedelta(seconds=triage._TRIAGE_PENDING_TIMEOUT_SECONDS + 60)
    row = _triage_row(old)
    app, db = _app(row)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"/triage/{uuid.uuid4()}")
    assert resp.json()["status"] == "failed"
    assert row.status == "failed"
    db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_fresh_pending_stays_pending():
    recent = datetime.now(timezone.utc) - timedelta(seconds=10)
    row = _triage_row(recent)
    app, _ = _app(row)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"/triage/{uuid.uuid4()}")
    assert resp.json()["status"] == "pending"
    assert row.status == "pending"
