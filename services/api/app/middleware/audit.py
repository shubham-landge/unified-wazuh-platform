import hashlib
import time
import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Endpoints whose request bodies must never be captured in audit logs.
_SENSITIVE_BODY_PATHS = {"/auth/login", "/profile/change-password"}


def _key_prefix(request: Request) -> str:
    key = request.headers.get("X-API-Key", "")
    if not key:
        return "anon"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        body_str = None
        if (
            request.method in ("POST", "PUT", "PATCH")
            and request.url.path not in _SENSITIVE_BODY_PATHS
        ):
            try:
                body_bytes = await request.body()
                body_str = body_bytes.decode("utf-8", errors="replace")[:2048]
            except Exception:
                body_str = None

        response: Response = await call_next(request)
        process_time = (time.time() - start_time) * 1000

        if body_str:
            logger.info(
                "audit path=%s method=%s status=%d latency=%.0fms client=%s key_prefix=%s body=%s",
                request.url.path,
                request.method,
                response.status_code,
                process_time,
                request.client.host if request.client else "unknown",
                _key_prefix(request),
                body_str,
            )
        else:
            logger.info(
                "audit path=%s method=%s status=%d latency=%.0fms client=%s key_prefix=%s",
                request.url.path,
                request.method,
                response.status_code,
                process_time,
                request.client.host if request.client else "unknown",
                _key_prefix(request),
            )

        response.headers["X-Process-Time-Ms"] = str(int(process_time))
        return response
