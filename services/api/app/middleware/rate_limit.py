import time
from collections import defaultdict
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_429_TOO_MANY_REQUESTS

from shared.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        api_key = request.headers.get("X-API-Key", "anonymous")
        now = time.time()
        window = 60

        self.requests[api_key] = [
            t for t in self.requests[api_key] if now - t < window
        ]

        if len(self.requests[api_key]) >= settings.api_rate_limit:
            raise HTTPException(
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {settings.api_rate_limit} requests per minute.",
            )

        self.requests[api_key].append(now)
        response = await call_next(request)

        response.headers["X-RateLimit-Limit"] = str(settings.api_rate_limit)
        response.headers["X-RateLimit-Remaining"] = str(
            settings.api_rate_limit - len(self.requests[api_key])
        )
        return response
