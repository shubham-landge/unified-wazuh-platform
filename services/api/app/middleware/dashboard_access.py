import ipaddress
import logging
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_403_FORBIDDEN
from starlette.requests import Request

from shared.config import settings

logger = logging.getLogger(__name__)

# Paths exempt from CIDR restriction (healthcheck, API docs, OpenAPI schema)
_EXEMPT_PREFIXES = ("/health", "/docs", "/redoc", "/openapi.json")


class DashboardAccessMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"

        try:
            ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            return JSONResponse(
                status_code=HTTP_403_FORBIDDEN,
                content={"detail": f"Invalid client IP: {client_ip}"},
            )

        for cidr_str in settings.dashboard_allowed_cidrs.split(","):
            cidr_str = cidr_str.strip()
            if not cidr_str:
                continue
            try:
                if ip_obj in ipaddress.ip_network(cidr_str, strict=False):
                    return await call_next(request)
            except ValueError:
                continue

        logger.warning("Access denied for IP %s (allowed: %s)", client_ip, settings.dashboard_allowed_cidrs)
        return JSONResponse(
            status_code=HTTP_403_FORBIDDEN,
            content={"detail": f"Access denied from {client_ip}"},
        )
