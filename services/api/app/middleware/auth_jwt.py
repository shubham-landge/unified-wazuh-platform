"""JWT-based authentication middleware for Phase 3A."""
import logging
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from shared.auth import verify_token, TokenData, has_permission
from shared.config import settings

logger = logging.getLogger(__name__)

security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> TokenData:
    """Validate JWT token and return user data."""
    token = credentials.credentials
    data = verify_token(token)
    if not data:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return data


async def get_current_user_optional(credentials: HTTPAuthorizationCredentials | None = Depends(HTTPBearer(auto_error=False))) -> TokenData | None:
    """Optional JWT validation (for endpoints that work with or without auth)."""
    if not credentials:
        return None
    token = credentials.credentials
    return verify_token(token)


def require_permission(permission: str):
    """Dependency for checking user permissions."""
    async def check_permission(user: TokenData = Depends(get_current_user)) -> TokenData:
        if not has_permission(user.permissions, permission):
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail=f"User does not have permission: {permission}",
            )
        return user
    return check_permission


def require_role(role: str):
    """Dependency for checking user role."""
    async def check_role(user: TokenData = Depends(get_current_user)) -> TokenData:
        if user.role != role and user.role != "admin":
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail=f"User must be {role} or admin",
            )
        return user
    return check_role
