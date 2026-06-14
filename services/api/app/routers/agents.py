import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.status import HTTP_202_ACCEPTED, HTTP_404_NOT_FOUND

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from shared.models.agent import AgentDefinition, AgentRun, AgentTask

router = APIRouter(prefix="/agents", tags=["agents"])


class RunCreate(BaseModel):
    definition_id: uuid.UUID
    trigger_type: str = Field(default="manual")
    trigger_ref: str | None = None


def _row(item) -> dict:
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


@router.get("/definitions")
async def list_definitions(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(AgentDefinition).where(AgentDefinition.is_active == True).order_by(desc(AgentDefinition.created_at)).limit(limit)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(AgentDefinition.tenant_id == tenant_uuid)
    
    rows = (await db.execute(query)).scalars().all()
    return {"status": "success", "count": len(rows), "definitions": [_row(r) for r in rows]}


@router.post("/runs", status_code=HTTP_202_ACCEPTED)
async def create_run(
    body: RunCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    defn = (await db.execute(
        select(AgentDefinition).where(AgentDefinition.id == body.definition_id)
    )).scalar_one_or_none()
    if not defn:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Agent definition not found")

    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
    else:
        tenant_uuid = uuid.UUID("00000000-0000-0000-0000-000000000001")

    run = AgentRun(
        definition_id=body.definition_id,
        tenant_id=tenant_uuid,
        trigger_type=body.trigger_type,
        trigger_ref=body.trigger_ref,
        status="pending",
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    try:
        import redis.asyncio as redis_async
        from shared.config import settings
        import json
        async with redis_async.from_url(settings.redis_url, decode_responses=True) as r:
            await r.lpush("agent_queue", json.dumps({"run_id": str(run.id)}))
    except Exception:
        pass

    return {"status": "accepted", "run_id": str(run.id)}


@router.get("/runs")
async def list_runs(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    q = select(AgentRun).order_by(desc(AgentRun.created_at)).limit(limit)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        q = q.where(AgentRun.tenant_id == tenant_uuid)
    rows = (await db.execute(q)).scalars().all()
    return {"status": "success", "count": len(rows), "runs": [_row(r) for r in rows]}


@router.get("/runs/{run_id}")
async def get_run(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(AgentRun).where(AgentRun.id == run_id)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(AgentRun.tenant_id == tenant_uuid)
    
    run = (await db.execute(query)).scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Run not found")

    tasks = (
        await db.execute(select(AgentTask).where(AgentTask.run_id == run_id).order_by(AgentTask.created_at))
    ).scalars().all()

    return {
        "status": "success",
        "run": _row(run),
        "tasks": [_row(t) for t in tasks],
    }
