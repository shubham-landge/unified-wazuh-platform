"""Authentication routes — login, logout, token refresh."""
import logging
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_400_BAD_REQUEST

from app.db import get_db
from shared.models.user import User
from shared.auth import verify_password, create_access_token, verify_token
from shared.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_email: str
    user_role: str


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate user and return JWT access token."""
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()

    if not user or not user.password_hash or not verify_password(request.password, user.password_hash):
        # Check lockout
        if user and user.locked_until:
            from datetime import datetime, timezone
            if datetime.now(timezone.utc) < user.locked_until:
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Account locked")
            user.locked_until = None

        # Increment failed attempts
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 5:
                from datetime import datetime, timezone, timedelta as td
                user.locked_until = datetime.now(timezone.utc) + td(minutes=15)
                logger.warning("Account locked after 5 failed attempts: %s", user.email)
            await db.commit()

        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Account is inactive")

    # Reset failed attempts on successful login
    user.failed_login_attempts = 0
    user.locked_until = None
    from datetime import datetime, timezone
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    # Create access token
    access_token = create_access_token(
        user_id=str(user.id),
        email=user.email,
        username=user.username,
        role=user.role,
        tenant_id=str(user.tenant_id) if user.tenant_id else None,
        permissions=user.permissions or [],
        expires_delta=timedelta(hours=settings.jwt_expiration_hours),
    )

    logger.info("User logged in: %s", user.email)
    return LoginResponse(
        access_token=access_token,
        user_email=user.email,
        user_role=user.role,
    )


@router.post("/logout")
async def logout(current_user = Depends(lambda: None)):
    """Logout (JWT is stateless, so this is just a signal to client to clear token)."""
    return {"status": "logout successful"}


@router.post("/refresh")
async def refresh_token(request: RefreshRequest):
    """Refresh access token (for this v1, we just validate the current token)."""
    data = verify_token(request.refresh_token)
    if not data:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    new_token = create_access_token(
        user_id=data.user_id,
        email=data.email,
        username=data.username,
        role=data.role,
        tenant_id=data.tenant_id,
        permissions=data.permissions,
        expires_delta=timedelta(hours=settings.jwt_expiration_hours),
    )
    return {"access_token": new_token, "token_type": "bearer"}
