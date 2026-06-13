import ipaddress
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_403_FORBIDDEN

from shared.config import settings

# Paths exempt from CIDR restriction (API docs, OpenAPI schema)
_EXEMPT_PREFIXES = ("/health", "/docs", "/redoc", "/openapi.json")


class DashboardAccessMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Allow API documentation through without CIDR check
        if any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"

        try:
            ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail=f"Invalid client IP: {client_ip}")

        for cidr_str in settings.dashboard_allowed_cidrs.split(","):
            cidr_str = cidr_str.strip()
            if not cidr_str:
                continue
            try:
                if ip_obj in ipaddress.ip_network(cidr_str, strict=False):
                    return await call_next(request)
            except ValueError:
                continue

        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail=f"Access denied from {client_ip}",
        )
