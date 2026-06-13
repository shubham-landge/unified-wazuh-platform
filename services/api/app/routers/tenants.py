import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.auth_jwt import get_current_user_optional, TokenData
from app.middleware.tenant_enforce import get_tenant_id
from shared.auth import has_permission
from shared.config import settings
from shared.models.tenant import Tenant
from shared.models.alert import Alert
from shared.models.case import Case
from shared.models.asset import Asset
from shared.models.user import User

router = APIRouter(prefix="/tenants", tags=["tenants"])

_DEFAULT_LIMIT = settings.api_default_page_limit


class TenantCreate(BaseModel):
    name: str
    slug: str
    config: dict = {}


class TenantUpdate(BaseModel):
    name: str | None = None
    slug: str | None = None
    config: dict | None = None
    is_active: bool | None = None


class BrandingUpdate(BaseModel):
    primary_color: str | None = None
    secondary_color: str | None = None
    company_name: str | None = None
    logo_url: str | None = None
    favicon_url: str | None = None
    custom_css: str | None = None


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


def _check_super_admin(user: TokenData | None = None):
    if user and (user.role == "admin" or has_permission(user.permissions, "admin:tenant")):
        return True
    raise HTTPException(status_code=403, detail="Super admin access required")


@router.get("")
async def list_tenants(
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    user: TokenData | None = Depends(get_current_user_optional),
):
    _check_super_admin(user)
    stmt = select(Tenant).order_by(desc(Tenant.created_at)).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {"status": "success", "count": len(rows), "tenants": [_row(r) for r in rows]}


@router.get("/{tenant_id_path}")
async def get_tenant(
    tenant_id_path: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    user: TokenData | None = Depends(get_current_user_optional),
):
    _check_super_admin(user)
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
    user: TokenData | None = Depends(get_current_user_optional),
):
    _check_super_admin(user)
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
    user: TokenData | None = Depends(get_current_user_optional),
):
    _check_super_admin(user)
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


@router.patch("/{tenant_id_path}/branding")
async def update_tenant_branding(
    tenant_id_path: uuid.UUID,
    body: BrandingUpdate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    user: TokenData | None = Depends(get_current_user_optional),
):
    _check_super_admin(user)
    stmt = select(Tenant).where(Tenant.id == tenant_id_path)
    row = (await db.execute(stmt)).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Tenant not found")

    current_config = dict(row.config) if row.config else {}
    branding = dict(current_config.get("branding", {}))
    update_data = body.model_dump(exclude_unset=True, exclude_none=True)
    branding.update(update_data)
    current_config["branding"] = branding
    row.config = current_config
    row.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(row)
    return {
        "status": "success",
        "branding": row.config.get("branding", {}),
    }


@router.delete("/{tenant_id_path}")
async def deactivate_tenant(
    tenant_id_path: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    user: TokenData | None = Depends(get_current_user_optional),
):
    _check_super_admin(user)
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
    user: TokenData | None = Depends(get_current_user_optional),
):
    _check_super_admin(user)
    stmt = select(Tenant).where(Tenant.id == tenant_id_path)
    row = (await db.execute(stmt)).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant_uuid = tenant_id_path
    alerts_count = (await db.execute(select(func.count(Alert.id)).where(Alert.tenant_id == tenant_uuid))).scalar() or 0
    cases_count = (await db.execute(select(func.count(Case.id)).where(Case.tenant_id == tenant_uuid))).scalar() or 0
    assets_count = (await db.execute(select(func.count(Asset.id)).where(Asset.tenant_id == tenant_uuid))).scalar() or 0
    users_count = (await db.execute(select(func.count(User.id)).where(User.tenant_id == tenant_uuid))).scalar() or 0

    return {
        "status": "success",
        "tenant_id": str(tenant_id_path),
        "stats": {
            "alerts_count": alerts_count,
            "cases_count": cases_count,
            "assets_count": assets_count,
            "users_count": users_count,
        },
    }
