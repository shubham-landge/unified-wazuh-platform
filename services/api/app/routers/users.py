"""User management routes (admin and analyst only)."""
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from starlette.status import HTTP_404_NOT_FOUND, HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN

from app.db import get_db
from app.middleware.auth_jwt import get_current_user, require_role
from app.middleware.tenant_enforce import get_tenant_id
from shared.models.user import User, ROLES
from shared.auth import hash_password, TokenData

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["users"])


class UserCreate(BaseModel):
    email: EmailStr
    username: str | None = None
    full_name: str | None = None
    password: str
    role: str = "viewer"


class UserResponse(BaseModel):
    id: str
    email: str
    username: str | None = None
    full_name: str | None = None
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: str | None = None
    is_active: bool | None = None


@router.get("", response_model=list[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(get_current_user),
    tenant_id: str | None = Depends(get_tenant_id),
):
    """List users in current tenant (admin/analyst only)."""
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Access denied")

    query = select(User)
    if tenant_id:
        query = query.where(User.tenant_id == tenant_id)
    query = query.order_by(User.created_at.desc())

    result = await db.execute(query)
    users = result.scalars().all()
    return users


@router.post("", response_model=UserResponse)
async def create_user(
    req: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(require_role("admin")),
    tenant_id: str | None = Depends(get_tenant_id),
):
    """Create a new user (admin only)."""
    # Check email not already exists
    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Email already exists")

    # Check role is valid
    if req.role not in ROLES:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=f"Invalid role: {req.role}")

    user = User(
        email=req.email,
        username=req.username,
        full_name=req.full_name,
        password_hash=hash_password(req.password),
        role=req.role,
        permissions=ROLES[req.role]["permissions"],
        tenant_id=tenant_id,
        is_active=True,
    )
    db.add(user)
    await db.commit()

    logger.info("User created: %s (role=%s)", user.email, user.role)
    return user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(get_current_user),
    tenant_id: str | None = Depends(get_tenant_id),
):
    """Get user by ID."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="User not found")

    # Enforce tenant: can only view users in own tenant (except admin)
    if tenant_id and user.tenant_id != tenant_id and current_user.role != "admin":
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Cannot view other tenant's users")

    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    req: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(require_role("admin")),
    tenant_id: str | None = Depends(get_tenant_id),
):
    """Update user (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="User not found")

    if req.full_name is not None:
        user.full_name = req.full_name
    if req.role is not None:
        if req.role not in ROLES:
            raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=f"Invalid role: {req.role}")
        user.role = req.role
        user.permissions = ROLES[req.role]["permissions"]
    if req.is_active is not None:
        user.is_active = req.is_active

    user.updated_at = datetime.now(timezone.utc)
    await db.commit()

    logger.info("User updated: %s", user.email)
    return user


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(require_role("admin")),
):
    """Delete user (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="User not found")

    await db.delete(user)
    await db.commit()

    logger.info("User deleted: %s", user.email)
    return {"status": "user deleted"}
