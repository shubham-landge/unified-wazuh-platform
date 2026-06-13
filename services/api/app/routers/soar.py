import uuid
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from shared.models.soar import SoarPlaybook, SoarTask, SoarExecution

router = APIRouter(prefix="/soar", tags=["soar"])


class PlaybookCreate(BaseModel):
    name: str
    trigger_type: str
    description: str | None = None
    steps: list = Field(default_factory=list)


class TaskCreate(BaseModel):
    name: str
    task_type: str
    playbook_id: uuid.UUID | None = None
    parameters: dict = Field(default_factory=dict)
    order_index: int = 0


class ExecutionCreate(BaseModel):
    playbook_id: uuid.UUID | None = None
    task_id: uuid.UUID | None = None
    alert_id: uuid.UUID | None = None
    triggered_by: str | None = None
    result: dict = Field(default_factory=dict)


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


@router.get("/playbooks")
async def list_playbooks(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    stmt = select(SoarPlaybook).order_by(desc(SoarPlaybook.created_at)).limit(limit)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        stmt = stmt.where(SoarPlaybook.tenant_id == tenant_uuid)
    
    rows = (await db.execute(stmt)).scalars().all()
    return {"status": "success", "count": len(rows), "playbooks": [_row(row) for row in rows]}


@router.post("/playbooks", status_code=201)
async def create_playbook(
    body: PlaybookCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
    else:
        tenant_uuid = uuid.UUID("00000000-0000-0000-0000-000000000001")

    playbook = SoarPlaybook(
        **body.model_dump(),
        tenant_id=tenant_uuid,
    )
    db.add(playbook)
    await db.commit()
    await db.refresh(playbook)
    return {"status": "success", "playbook": _row(playbook)}


@router.get("/tasks")
async def list_tasks(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    stmt = select(SoarTask).order_by(desc(SoarTask.created_at)).limit(limit)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        stmt = stmt.where(SoarTask.tenant_id == tenant_uuid)
    
    rows = (await db.execute(stmt)).scalars().all()
    return {"status": "success", "count": len(rows), "tasks": [_row(row) for row in rows]}


@router.post("/tasks", status_code=201)
async def create_task(
    body: TaskCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
    else:
        tenant_uuid = uuid.UUID("00000000-0000-0000-0000-000000000001")

    task = SoarTask(
        **body.model_dump(),
        tenant_id=tenant_uuid,
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)
    return {"status": "success", "task": _row(task)}


@router.get("/executions")
async def list_executions(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    stmt = select(SoarExecution).order_by(desc(SoarExecution.created_at)).limit(limit)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        stmt = stmt.where(SoarExecution.tenant_id == tenant_uuid)
    
    rows = (await db.execute(stmt)).scalars().all()
    return {"status": "success", "count": len(rows), "executions": [_row(row) for row in rows]}


@router.post("/executions", status_code=201)
async def create_execution(
    body: ExecutionCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
    else:
        tenant_uuid = uuid.UUID("00000000-0000-0000-0000-000000000001")

    execution = SoarExecution(
        **body.model_dump(),
        tenant_id=tenant_uuid,
    )
    db.add(execution)
    await db.commit()
    await db.refresh(execution)
    return {"status": "success", "execution": _row(execution)}
