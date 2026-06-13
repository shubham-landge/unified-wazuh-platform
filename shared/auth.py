"""Authentication and authorization utilities."""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from shared.config import settings

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenData(BaseModel):
    user_id: str
    email: str
    username: str | None = None
    role: str = "viewer"
    tenant_id: str | None = None
    permissions: list[str] = []
    exp: datetime | None = None


def hash_password(password: str) -> str:
    """Hash a plaintext password."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    user_id: str,
    email: str,
    username: str | None = None,
    role: str = "viewer",
    tenant_id: str | None = None,
    permissions: list[str] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT access token."""
    if expires_delta is None:
        expires_delta = timedelta(hours=settings.jwt_expiration_hours)

    expire = datetime.now(timezone.utc) + expires_delta
    data = TokenData(
        user_id=user_id,
        email=email,
        username=username,
        role=role,
        tenant_id=tenant_id,
        permissions=permissions or [],
        exp=expire,
    )
    encoded = jwt.encode(
        data.model_dump(),
        settings.jwt_secret_key.get_secret_value(),
        algorithm="HS256",
    )
    return encoded


def verify_token(token: str) -> TokenData | None:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=["HS256"],
        )
        user_id = payload.get("user_id")
        if not user_id:
            return None
        return TokenData(**payload)
    except JWTError:
        return None


def has_permission(user_permissions: list[str], required: str) -> bool:
    """Check if user has a permission. Wildcards are verb-scoped: read:* only grants read:anything."""
    if required in user_permissions:
        return True
    perm_parts = required.split(":")
    if len(perm_parts) == 2:
        wildcard = f"{perm_parts[0]}:*"
        if wildcard in user_permissions:
            return True
    return False
