import uuid
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from shared.config import settings
from shared.models.ticketing import TicketingConfig, TicketLink
from shared.connectors.ticket_servicenow import ServiceNowConnector
from shared.connectors.ticket_jira import JiraConnector

router = APIRouter(prefix="/ticketing", tags=["ticketing"])

_DEFAULT_LIMIT = settings.api_default_page_limit

_SENSITIVE_CONFIG_KEYS = {"password", "api_token", "api_key", "token", "secret", "credentials"}


def _mask_sensitive_config(config: dict) -> dict:
    masked = {}
    for key, value in config.items():
        if any(s in key.lower() for s in _SENSITIVE_CONFIG_KEYS):
            masked[key] = "***"
        elif isinstance(value, dict):
            masked[key] = _mask_sensitive_config(value)
        else:
            masked[key] = value
    return masked


class TicketingConfigBody(BaseModel):
    provider: str
    config: dict


class TestConnectionBody(BaseModel):
    provider: str
    config: dict


@router.get("/config")
async def list_configs(
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(TicketingConfig)
    if tenant_id:
        import uuid
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(TicketingConfig.tenant_id == tenant_uuid)
    query = query.limit(limit)

    result = await db.execute(query)
    configs = result.scalars().all()
    return {
        "status": "success",
        "configs": [
            {
                "id": str(c.id),
                "provider": c.provider,
                "config": _mask_sensitive_config(c.config or {}),
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
    tenant_id: str | None = Depends(get_tenant_id),
):
    tenant_uuid = uuid.UUID(tenant_id) if tenant_id else None
    result = await db.execute(
        select(TicketingConfig).where(
            TicketingConfig.provider == body.provider,
            TicketingConfig.tenant_id == tenant_uuid,
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        existing.config = body.config
        existing.is_active = True
    else:
        existing = TicketingConfig(
            provider=body.provider,
            tenant_id=tenant_uuid,
            config=body.config,
            is_active=True,
        )
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
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Invalid case ID")
    
    query = select(TicketLink).where(TicketLink.case_id == uid)
    if tenant_id:
        import uuid
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(TicketLink.tenant_id == tenant_uuid)
    
    result = await db.execute(query)
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
