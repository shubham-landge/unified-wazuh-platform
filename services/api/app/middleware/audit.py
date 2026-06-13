import hashlib
import time
import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


def _key_prefix(request: Request) -> str:
    key = request.headers.get("X-API-Key", "")
    if not key:
        return "anon"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response: Response = await call_next(request)
        process_time = (time.time() - start_time) * 1000

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
