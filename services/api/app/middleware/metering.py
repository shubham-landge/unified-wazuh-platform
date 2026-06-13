import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

EXEMPT_PATHS = {
    "/health", "/health/ready", "/docs", "/redoc", "/openapi.json",
    "/usage/record", "/usage/limits", "/usage/summary", "/usage/records",
}

_counter: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
_counter_lock = Lock()
_FLUSH_INTERVAL = 300  # 5 minutes
_last_flush = time.time()


class UsageMeteringMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(e) for e in EXEMPT_PATHS):
            return await call_next(request)

        tenant_id = getattr(request.state, "tenant_id", None) or "system"
        method = request.method

        with _counter_lock:
            _counter[tenant_id]["api_calls"] += 1
            _counter[tenant_id][f"{method}_calls"] += 1

        response = await call_next(request)

        global _last_flush
        now = time.time()
        if now - _last_flush > _FLUSH_INTERVAL:
            _last_flush = now
            logger.debug("Metering counters: %d tenants tracked", len(_counter))

        return response


def get_metering_snapshot() -> dict:
    with _counter_lock:
        snapshot = {k: dict(v) for k, v in _counter.items()}
        return snapshot


def reset_metering():
    with _counter_lock:
        _counter.clear()