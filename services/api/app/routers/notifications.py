import uuid
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from shared.models.notification import (
    NotificationChannel,
    NotificationRule,
    NotificationEvent,
)

router = APIRouter(prefix="/notifications", tags=["notifications"])


class ChannelCreate(BaseModel):
    name: str
    channel_type: str
    destination: str
    config: dict = Field(default_factory=dict)
    severity_filter: str | None = None


class RuleCreate(BaseModel):
    name: str
    event_type: str
    channel_id: uuid.UUID | None = None
    severity: str | None = None
    conditions: dict = Field(default_factory=dict)


def _row(item):
    data = {}
    for key, value in item.__dict__.items():
        if key.startswith("_"):
            continue
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        elif isinstance(value, uuid.UUID):
            value = str(value)
        data[key] = value
    return data


@router.get("/channels")
async def list_channels(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    rows = (
        await db.execute(select(NotificationChannel).order_by(desc(NotificationChannel.created_at)).limit(limit))
    ).scalars().all()
    return {"status": "success", "count": len(rows), "channels": [_row(row) for row in rows]}


@router.post("/channels", status_code=201)
async def create_channel(
    body: ChannelCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    channel = NotificationChannel(**body.model_dump(), tenant_id=uuid.UUID("00000000-0000-0000-0000-000000000001"))
    db.add(channel)
    await db.commit()
    await db.refresh(channel)
    return {"status": "success", "channel": _row(channel)}


@router.get("/rules")
async def list_rules(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    rows = (
        await db.execute(select(NotificationRule).order_by(desc(NotificationRule.created_at)).limit(limit))
    ).scalars().all()
    return {"status": "success", "count": len(rows), "rules": [_row(row) for row in rows]}


@router.post("/rules", status_code=201)
async def create_rule(
    body: RuleCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    rule = NotificationRule(**body.model_dump(), tenant_id=uuid.UUID("00000000-0000-0000-0000-000000000001"))
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return {"status": "success", "rule": _row(rule)}


@router.get("/events")
async def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    rows = (
        await db.execute(select(NotificationEvent).order_by(desc(NotificationEvent.created_at)).limit(limit))
    ).scalars().all()
    return {"status": "success", "count": len(rows), "events": [_row(row) for row in rows]}
