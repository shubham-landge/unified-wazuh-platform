import uuid
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id, require_tenant_uuid
from shared.models.threat_intel import ThreatIntelFeed, ThreatIntelIndicator

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


class FeedCreate(BaseModel):
    name: str
    source_url: str
    feed_type: str
    refresh_interval_minutes: int = 60
    parser_config: dict = Field(default_factory=dict)


class IndicatorCreate(BaseModel):
    feed_id: uuid.UUID | None = None
    indicator_type: str
    value: str
    confidence: float | None = None
    severity: str | None = None
    context: dict = Field(default_factory=dict)


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


@router.get("/feeds")
async def list_feeds(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    stmt = select(ThreatIntelFeed).order_by(desc(ThreatIntelFeed.created_at)).limit(limit)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        stmt = stmt.where(ThreatIntelFeed.tenant_id == tenant_uuid)
    
    rows = (await db.execute(stmt)).scalars().all()
    return {"status": "success", "count": len(rows), "feeds": [_row(row) for row in rows]}


@router.post("/feeds", status_code=201)
async def create_feed(
    body: FeedCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    tenant_uuid = require_tenant_uuid(tenant_id)

    feed = ThreatIntelFeed(
        **body.model_dump(),
        tenant_id=tenant_uuid,
    )
    db.add(feed)
    await db.commit()
    await db.refresh(feed)
    return {"status": "success", "feed": _row(feed)}


@router.get("/indicators")
async def list_indicators(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    stmt = select(ThreatIntelIndicator).order_by(desc(ThreatIntelIndicator.created_at)).limit(limit)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        stmt = stmt.where(ThreatIntelIndicator.tenant_id == tenant_uuid)
    
    rows = (await db.execute(stmt)).scalars().all()
    return {"status": "success", "count": len(rows), "indicators": [_row(row) for row in rows]}


@router.post("/indicators", status_code=201)
async def create_indicator(
    body: IndicatorCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    tenant_uuid = require_tenant_uuid(tenant_id)

    indicator = ThreatIntelIndicator(
        **body.model_dump(),
        tenant_id=tenant_uuid,
    )
    db.add(indicator)
    await db.commit()
    await db.refresh(indicator)
    return {"status": "success", "indicator": _row(indicator)}
