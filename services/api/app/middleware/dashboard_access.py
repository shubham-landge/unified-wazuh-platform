import ipaddress
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_403_FORBIDDEN

from shared.config import settings


class DashboardAccessMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith(("/dashboard", "/static", "/", "/alerts", "/cases", "/vulnerabilities", "/assets", "/audit", "/health")):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        allowed = False

        for cidr_str in settings.dashboard_allowed_cidrs.split(","):
            cidr_str = cidr_str.strip()
            if not cidr_str:
                continue
            try:
                if ipaddress.ip_address(client_ip) in ipaddress.ip_network(cidr_str, strict=False):
                    allowed = True
                    break
            except ValueError:
                continue

        if not allowed:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail=f"Access denied from {client_ip}",
            )

        return await call_next(request)
