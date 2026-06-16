import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.auth_jwt import get_current_user_optional, TokenData
from app.middleware.tenant_enforce import get_tenant_id, require_tenant_uuid
from shared.auth import has_permission
from shared.models.tenant import Tenant
from shared.models.usage import TenantUsage, UsageRecord
from shared.config import settings

router = APIRouter(prefix="/usage", tags=["usage"])

_DEFAULT_LIMIT = settings.api_default_page_limit


class UsageRecordCreate(BaseModel):
    event_type: str
    resource_id: str | None = None
    resource_type: str = "general"
    extra_meta: dict = Field(default_factory=dict)


_DEFAULT_LIMITS = {
    "alerts_per_month": settings.metering_default_alert_limit,
    "api_calls_per_month": settings.metering_default_api_limit,
    "storage_gb": settings.metering_default_storage_gb,
    "ai_triage_per_month": settings.metering_default_ai_triage_limit,
}


def _get_per_tenant_limits(tenant_config: dict | None) -> dict:
    limits = dict(_DEFAULT_LIMITS)
    if tenant_config:
        overrides = tenant_config.get("limits", {})
        limits.update(overrides)
    return limits


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


@router.get("/summary")
async def get_usage_summary(
    period: str = Query(default="current", pattern="^(current|last_30d|custom)$"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Tenant context required")
    tenant_uuid = uuid.UUID(tenant_id)

    now = datetime.now(timezone.utc)
    if period == "current":
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        period_end = now
    elif period == "last_30d":
        period_start = now - timedelta(days=30)
        period_end = now
    else:
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        period_end = now

    stmt = select(TenantUsage).where(
        TenantUsage.tenant_id == tenant_uuid,
        TenantUsage.period_start >= period_start,
        TenantUsage.period_end <= period_end,
    ).order_by(desc(TenantUsage.period_start)).limit(1)
    usage = (await db.execute(stmt)).scalars().first()

    if not usage:
        counts_stmt = select(
            func.count().label("alerts_count"),
        ).select_from(TenantUsage).where(
            TenantUsage.tenant_id == tenant_uuid
        )
        return {
            "status": "success",
            "period": period,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "summary": {
                "alerts_count": 0,
                "api_calls_count": 0,
                "cases_count": 0,
                "agents_count": 0,
                "storage_mb": 0.0,
                "ai_triage_count": 0,
                "report_count": 0,
                "total_score": 0,
            },
        }

    return {"status": "success", "period": period, "summary": _row(usage)}


@router.get("/records")
async def list_usage_records(
    limit: int = Query(default=50, ge=1, le=500),
    event_type: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    stmt = select(UsageRecord).order_by(desc(UsageRecord.recorded_at))
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        stmt = stmt.where(UsageRecord.tenant_id == tenant_uuid)
    if event_type:
        stmt = stmt.where(UsageRecord.event_type == event_type)
    stmt = stmt.limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {"status": "success", "count": len(rows), "records": [_row(row) for row in rows]}


@router.post("/record", status_code=201)
async def record_usage_event(
    body: UsageRecordCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    tenant_uuid = require_tenant_uuid(tenant_id)

    record = UsageRecord(
        tenant_id=tenant_uuid,
        event_type=body.event_type,
        resource_id=body.resource_id,
        resource_type=body.resource_type,
        extra_meta=body.extra_meta,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return {"status": "success", "record": _row(record)}


@router.get("/limits")
async def get_usage_limits(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    limits = dict(_DEFAULT_LIMITS)
    if tenant_id:
        tenant_stmt = select(Tenant).where(Tenant.id == uuid.UUID(tenant_id))
        tenant = (await db.execute(tenant_stmt)).scalars().first()
        if tenant:
            limits = _get_per_tenant_limits(tenant.config)
    return {
        "status": "success",
        "limits": limits,
    }


@router.get("/all-tenants")
async def get_all_tenants_usage(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    user: TokenData | None = Depends(get_current_user_optional),
):
    if not user or (user.role != "admin" and not has_permission(user.permissions, "admin:tenant")):
        raise HTTPException(status_code=403, detail="Super admin access required")

    tenants = (await db.execute(select(Tenant).where(Tenant.is_active == True))).scalars().all()
    results = []
    now = datetime.now(timezone.utc)
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    tenant_ids = [tenant.id for tenant in tenants]
    usage_rows = {}
    if tenant_ids:
        usage_stmt = select(TenantUsage).where(
            TenantUsage.tenant_id.in_(tenant_ids),
            TenantUsage.period_start >= period_start,
        ).order_by(desc(TenantUsage.period_start))
        usage_result = await db.execute(usage_stmt)
        for row in usage_result.scalars().all():
            if row.tenant_id not in usage_rows:
                usage_rows[row.tenant_id] = row

    for tenant in tenants:
        usage = usage_rows.get(tenant.id)
        limits = _get_per_tenant_limits(tenant.config)
        usage_data = _row(usage) if usage else {
            "alerts_count": 0, "api_calls_count": 0, "storage_mb": 0.0,
            "ai_triage_count": 0, "total_score": 0,
        }
        usage_data["tenant_name"] = tenant.name
        usage_data["tenant_slug"] = tenant.slug
        usage_data["limits"] = limits
        results.append(usage_data)

    return {"status": "success", "count": len(results), "tenants": results}
