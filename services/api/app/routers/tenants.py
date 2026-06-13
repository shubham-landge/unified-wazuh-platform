import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from shared.models.tenant import Tenant

router = APIRouter(prefix="/tenants", tags=["tenants"])


class TenantCreate(BaseModel):
    name: str
    slug: str
    config: dict = {}


class TenantUpdate(BaseModel):
    name: str | None = None
    slug: str | None = None
    config: dict | None = None
    is_active: bool | None = None


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


def _check_super_admin(tenant_id: str | None):
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Super admin access required")
    if tenant_id == "00000000-0000-0000-0000-000000000001":
        return True
    raise HTTPException(status_code=403, detail="Super admin access required")


@router.get("")
async def list_tenants(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    _check_super_admin(tenant_id)
    stmt = select(Tenant).order_by(desc(Tenant.created_at))
    rows = (await db.execute(stmt)).scalars().all()
    return {"status": "success", "count": len(rows), "tenants": [_row(r) for r in rows]}


@router.get("/{tenant_id_path}")
async def get_tenant(
    tenant_id_path: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    _check_super_admin(tenant_id)
    stmt = select(Tenant).where(Tenant.id == tenant_id_path)
    row = (await db.execute(stmt)).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"status": "success", "tenant": _row(row)}


@router.post("", status_code=201)
async def create_tenant(
    body: TenantCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    _check_super_admin(tenant_id)
    existing = (await db.execute(select(Tenant).where(Tenant.slug == body.slug))).scalars().first()
    if existing:
        raise HTTPException(status_code=409, detail="Tenant with this slug already exists")

    tenant = Tenant(name=body.name, slug=body.slug, config=body.config)
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    return {"status": "success", "tenant": _row(tenant)}


@router.patch("/{tenant_id_path}")
async def update_tenant(
    tenant_id_path: uuid.UUID,
    body: TenantUpdate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    _check_super_admin(tenant_id)
    stmt = select(Tenant).where(Tenant.id == tenant_id_path)
    row = (await db.execute(stmt)).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Tenant not found")

    update_data = body.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(row, key, value)
    row.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(row)
    return {"status": "success", "tenant": _row(row)}


@router.delete("/{tenant_id_path}")
async def deactivate_tenant(
    tenant_id_path: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    _check_super_admin(tenant_id)
    stmt = select(Tenant).where(Tenant.id == tenant_id_path)
    row = (await db.execute(stmt)).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Tenant not found")

    row.is_active = False
    row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "success", "message": "Tenant deactivated"}


@router.get("/{tenant_id_path}/stats")
async def get_tenant_stats(
    tenant_id_path: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    _check_super_admin(tenant_id)
    stmt = select(Tenant).where(Tenant.id == tenant_id_path)
    row = (await db.execute(stmt)).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Tenant not found")

    return {
        "status": "success",
        "tenant_id": str(tenant_id_path),
        "stats": {
            "alerts_count": 0,
            "cases_count": 0,
            "assets_count": 0,
            "users_count": 0,
            "active_days": 0,
        },
    }
