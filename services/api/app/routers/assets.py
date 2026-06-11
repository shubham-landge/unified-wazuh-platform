from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.db import get_db
from shared.models.asset import Asset
from app.middleware.auth import validate_api_key

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("")
async def list_assets(
    status: str | None = Query(default=None),
    group: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    query = select(Asset).order_by(desc(Asset.last_seen))

    if status:
        query = query.where(Asset.status == status)
    if group:
        query = query.where(Asset.groups.any(group))

    query = query.limit(limit)
    result = await db.execute(query)
    assets = result.scalars().all()

    return {
        "status": "success",
        "count": len(assets),
        "assets": [
            {
                "id": str(a.id),
                "agent_id": a.agent_id,
                "agent_name": a.agent_name,
                "agent_ip": a.agent_ip,
                "os_name": a.os_name,
                "os_version": a.os_version,
                "status": a.status,
                "groups": a.groups,
                "criticality": a.criticality,
                "owner": a.owner,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            }
            for a in assets
        ],
    }
