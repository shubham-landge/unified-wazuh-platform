import json
import uuid

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from shared.config import settings
from shared.models.osint import OsintTarget, OsintResult

router = APIRouter(prefix="/osint", tags=["osint"])
ALLOWED_TARGET_TYPES = {"username", "email", "domain"}


class LookupRequest(BaseModel):
    target_type: str
    target_value: str


def _row(item):
    data = {}
    for key, value in item.__dict__.items():
        if key.startswith("_"):
            continue
        if isinstance(value, uuid.UUID):
            value = str(value)
        elif hasattr(value, "isoformat"):
            value = value.isoformat()
        data[key] = value
    return data


@router.post("/lookup", status_code=202)
async def create_lookup(
    body: LookupRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    target_type = body.target_type.strip().lower()
    if target_type not in ALLOWED_TARGET_TYPES:
        raise HTTPException(status_code=400, detail="Invalid target_type")

    if not tenant_id:
        raise HTTPException(status_code=403, detail="Tenant context required")
    tenant_uuid = uuid.UUID(tenant_id)

    target = OsintTarget(
        tenant_id=tenant_uuid,
        target_type=target_type,
        target_value=body.target_value.strip(),
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    client = redis.from_url(settings.redis_url, decode_responses=True)
    await client.lpush(
        "osint_queue",
        json.dumps(
            {
                "target_id": str(target.id),
                "tenant_id": str(target.tenant_id),
                "target_type": target.target_type,
                "target_value": target.target_value,
            }
        ),
    )
    return {
        "status": "accepted",
        "target_id": str(target.id),
        "target": _row(target),
    }


@router.get("/targets")
async def list_targets(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    stmt = select(OsintTarget)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        stmt = stmt.where(OsintTarget.tenant_id == tenant_uuid)
    
    rows = (
        await db.execute(stmt.order_by(desc(OsintTarget.created_at)).offset(offset).limit(limit))
    ).scalars().all()
    return {"status": "success", "count": len(rows), "targets": [_row(row) for row in rows]}


@router.get("/results/{target_id}")
async def list_results(
    target_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    stmt = select(OsintTarget).where(OsintTarget.id == target_id)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        stmt = stmt.where(OsintTarget.tenant_id == tenant_uuid)
    
    target = (await db.execute(stmt)).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    rows = (
        await db.execute(
            select(OsintResult)
            .where(OsintResult.target_id == target_id)
            .order_by(desc(OsintResult.created_at))
        )
    ).scalars().all()
    return {
        "status": "success",
        "target": _row(target),
        "count": len(rows),
        "results": [_row(row) for row in rows],
    }
