from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.db import get_db
from app.models.audit_log import AuditLog
from app.middleware.auth import validate_api_key

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def list_audit_logs(
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    query = select(AuditLog).order_by(desc(AuditLog.created_at))

    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)

    query = query.limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()

    return {
        "status": "success",
        "count": len(logs),
        "entries": [
            {
                "id": str(log.id),
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "actor": log.actor,
                "status": log.status,
                "latency_ms": log.latency_ms,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
    }
