import uuid
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.db import get_db
from app.middleware.auth import validate_api_key
from shared.models.ticketing import TicketingConfig, TicketLink
from shared.connectors.ticket_servicenow import ServiceNowConnector
from shared.connectors.ticket_jira import JiraConnector

router = APIRouter(prefix="/ticketing", tags=["ticketing"])


class TicketingConfigBody(BaseModel):
    provider: str
    config: dict


class TestConnectionBody(BaseModel):
    provider: str
    config: dict


@router.get("/config")
async def list_configs(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    result = await db.execute(select(TicketingConfig))
    configs = result.scalars().all()
    return {
        "status": "success",
        "configs": [
            {
                "id": str(c.id),
                "provider": c.provider,
                "config": c.config,
                "is_active": c.is_active,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in configs
        ],
    }


@router.put("/config")
async def upsert_config(
    body: TicketingConfigBody,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    result = await db.execute(
        select(TicketingConfig).where(TicketingConfig.provider == body.provider)
    )
    existing = result.scalar_one_or_none()
    if existing:
        existing.config = body.config
        existing.is_active = True
    else:
        existing = TicketingConfig(provider=body.provider, config=body.config, is_active=True)
        db.add(existing)
    await db.commit()
    return {"status": "success", "provider": body.provider}


@router.post("/sync/{case_id}")
async def sync_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Invalid case ID")
    return {"status": "accepted", "case_id": case_id, "message": "Sync queued"}


@router.get("/links/{case_id}")
async def get_case_links(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Invalid case ID")
    result = await db.execute(
        select(TicketLink).where(TicketLink.case_id == uid)
    )
    links = result.scalars().all()
    return {
        "status": "success",
        "links": [
            {
                "id": str(l.id),
                "provider": l.provider,
                "remote_ticket_id": l.remote_ticket_id,
                "remote_ticket_url": l.remote_ticket_url,
                "sync_status": l.sync_status,
                "last_synced_at": l.last_synced_at.isoformat() if l.last_synced_at else None,
            }
            for l in links
        ],
    }


@router.post("/test")
async def test_connection(
    body: TestConnectionBody,
):
    provider = body.provider.lower()
    cfg = body.config
    if provider == "servicenow":
        conn = ServiceNowConnector(
            instance=cfg.get("instance"),
            user=cfg.get("user"),
            password=cfg.get("password"),
        )
    elif provider == "jira":
        conn = JiraConnector(
            url=cfg.get("url"),
            email=cfg.get("email"),
            api_token=cfg.get("api_token"),
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")
    health = await conn.health()
    return {"status": "success" if health.get("connected") else "error", "health": health}
