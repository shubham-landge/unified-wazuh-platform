import json
import uuid
import logging
from datetime import datetime, timezone

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from shared.config import settings
from shared.models.playbook import Playbook, PlaybookRun

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


class PlaybookCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = None
    trigger: dict = Field(default_factory=dict)
    actions: list = Field(default_factory=list)
    priority: int = 100
    is_active: bool = True


class PlaybookUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    trigger: dict | None = None
    actions: list | None = None
    priority: int | None = None
    is_active: bool | None = None


class RunRequest(BaseModel):
    alert_id: str | None = None
    case_id: str | None = None
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


@router.get("")
async def list_playbooks(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(Playbook).order_by(Playbook.priority, Playbook.name)
    if tenant_id:
        query = query.where(Playbook.tenant_id == uuid.UUID(tenant_id))
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    rows = result.scalars().all()
    return {
        "status": "success",
        "count": len(rows),
        "playbooks": [_row(r) for r in rows],
    }


@router.get("/runs")
async def list_runs(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(PlaybookRun).order_by(desc(PlaybookRun.created_at))
    if tenant_id:
        query = query.where(PlaybookRun.tenant_id == uuid.UUID(tenant_id))
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    rows = result.scalars().all()
    return {
        "status": "success",
        "count": len(rows),
        "runs": [_row(r) for r in rows],
    }


@router.post("", status_code=201)
async def create_playbook(
    payload: PlaybookCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    playbook = Playbook(
        name=payload.name,
        description=payload.description,
        trigger=payload.trigger,
        actions=payload.actions,
        priority=payload.priority,
        is_active=payload.is_active,
        tenant_id=uuid.UUID(tenant_id) if tenant_id else None,
    )
    db.add(playbook)
    await db.commit()
    await db.refresh(playbook)
    return {"status": "success", "playbook": _row(playbook)}


@router.patch("/{playbook_id}")
async def update_playbook(
    playbook_id: uuid.UUID,
    payload: PlaybookUpdate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(Playbook).where(Playbook.id == playbook_id)
    if tenant_id:
        query = query.where(Playbook.tenant_id == uuid.UUID(tenant_id))
    result = await db.execute(query)
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        if value is not None:
            setattr(playbook, key, value)
    await db.commit()
    await db.refresh(playbook)
    return {"status": "success", "playbook": _row(playbook)}


@router.delete("/{playbook_id}", status_code=204)
async def delete_playbook(
    playbook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(Playbook).where(Playbook.id == playbook_id)
    if tenant_id:
        query = query.where(Playbook.tenant_id == uuid.UUID(tenant_id))
    result = await db.execute(query)
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    await db.delete(playbook)
    await db.commit()


@router.post("/{playbook_id}/run")
async def run_playbook(
    playbook_id: uuid.UUID,
    payload: RunRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(Playbook).where(Playbook.id == playbook_id)
    if tenant_id:
        query = query.where(Playbook.tenant_id == uuid.UUID(tenant_id))
    result = await db.execute(query)
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # Create a pending run record
    run = PlaybookRun(
        playbook_id=playbook_id,
        alert_id=uuid.UUID(payload.alert_id) if payload.alert_id else None,
        case_id=uuid.UUID(payload.case_id) if payload.case_id else None,
        status="pending",
        actions_total=len(playbook.actions),
        started_at=datetime.now(timezone.utc),
        tenant_id=uuid.UUID(tenant_id) if tenant_id else None,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    # Push to playbook_queue for the worker to consume
    try:
        r = await redis.from_url(settings.redis_url, decode_responses=True)
        await r.lpush(
            "playbook_queue",
            json.dumps({
                "playbook_id": str(playbook_id),
                "run_id": str(run.id),
                "alert_id": payload.alert_id,
                "case_id": payload.case_id,
                "context": payload.context,
                "tenant_id": tenant_id,
            }),
        )
        await r.close()
    except Exception as e:
        logger.error("Failed to enqueue playbook run: %s", e)

    return {
        "status": "queued",
        "run": _row(run),
    }
