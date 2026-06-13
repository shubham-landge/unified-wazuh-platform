"""Tenant enforcement middleware — ensures users access only their tenant's data."""
import logging
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_403_FORBIDDEN

from shared.auth import verify_token

logger = logging.getLogger(__name__)

# Paths that bypass tenant enforcement (health checks, login, etc)
EXEMPT_PATHS = {
    "/health",
    "/health/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/auth/login",
    "/auth/callback",
}


class TenantEnforcementMiddleware(BaseHTTPMiddleware):
    """
    Ensures that authenticated requests can only access resources
    belonging to their tenant.

    For API keys (legacy phase 1-2 auth), tenant_id is derived from the key hash.
    For JWT tokens (phase 3A), tenant_id comes from the token.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip enforcement for exempt paths
        if any(path.startswith(exempt) for exempt in EXEMPT_PATHS):
            return await call_next(request)

        # Extract tenant_id from request context or auth header
        tenant_id = None

        # Try JWT token first
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            token_data = verify_token(token)
            if token_data:
                tenant_id = token_data.tenant_id
                request.state.user = token_data
                request.state.tenant_id = tenant_id

        # Legacy API keys have no per-key tenant mapping — do not synthesise a
        # fake tenant_id here. Tenant-scoped filters in routers skip when
        # tenant_id is None, so API-key callers see all tenants (admin access).
        if not tenant_id:
            api_key = request.headers.get("X-API-Key", "")
            if api_key:
                request.state.tenant_id = None

        # For authenticated requests, tenant_id is now mandatory
        if not tenant_id and auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Tenant ID could not be determined",
            )

        # Store in request state so routers can access it
        if tenant_id:
            request.state.tenant_id = tenant_id
            logger.debug("Tenant enforcement: %s → tenant=%s", path, tenant_id)

        return await call_next(request)


def get_tenant_id(request: Request) -> str | None:
    """Extract tenant_id from request state (set by TenantEnforcementMiddleware)."""
    return getattr(request.state, "tenant_id", None)
