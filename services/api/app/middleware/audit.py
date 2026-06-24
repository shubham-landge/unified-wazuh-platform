import asyncio
import hashlib
import time
import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from shared.models.audit_log import AuditLog
from services.api.app.db import async_session

logger = logging.getLogger(__name__)

# Endpoints whose request bodies must never be captured in audit logs.
_SENSITIVE_BODY_PATHS = {"/auth/login", "/profile/change-password"}


def _key_prefix(request: Request) -> str:
    key = request.headers.get("X-API-Key", "")
    if not key:
        return "anon"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def _actor_from_request(request: Request) -> tuple[str, str]:
    """Extract (actor_id, actor_type) from the request state or headers."""
    # Prefer the authenticated user set by the auth middleware.
    user = getattr(request.state, "user", None)
    if user:
        return (str(user.get("id", "unknown")), "user")

    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        return (_key_prefix(request), "api_key")

    return ("anonymous", "system")


async def _write_audit_log(
    path: str,
    method: str,
    status_code: int,
    latency_ms: int,
    client_host: str | None,
    actor: str,
    actor_type: str,
    body_str: str | None,
    tenant_id: str | None = None,
) -> None:
    """Persist an audit log row in a background task (fire-and-forget)."""
    try:
        async with async_session() as session:
            entry = AuditLog(
                action=f"{method} {path}",
                resource_type="api_endpoint",
                resource_id=path,
                actor=actor,
                actor_type=actor_type,
                details={"body": body_str} if body_str else None,
                ip_address=client_host,
                user_agent=None,  # populated below if available
                status="success" if status_code < 400 else "error",
                error_message=None if status_code < 400 else f"HTTP {status_code}",
                latency_ms=latency_ms,
                tenant_id=tenant_id,
            )
            session.add(entry)
            await session.commit()
    except Exception as exc:
        logger.warning("Failed to write audit log: %s", exc)


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
            except Exception as e:
                logger.warning("Failed to read request body for audit: %s", e)
                body_str = None

        response: Response = await call_next(request)
        process_time = (time.time() - start_time) * 1000

        client_host = request.client.host if request.client else None

        if body_str:
            logger.info(
                "audit path=%s method=%s status=%d latency=%.0fms client=%s key_prefix=%s body=%s",
                request.url.path,
                request.method,
                response.status_code,
                process_time,
                client_host or "unknown",
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
                client_host or "unknown",
                _key_prefix(request),
            )

        # Fire-and-forget: write to DB non-blocking.
        actor, actor_type = _actor_from_request(request)
        tenant_id = getattr(request.state, "tenant_id", None)
        asyncio.create_task(
            _write_audit_log(
                path=request.url.path,
                method=request.method,
                status_code=response.status_code,
                latency_ms=int(process_time),
                client_host=client_host,
                actor=actor,
                actor_type=actor_type,
                body_str=body_str,
                tenant_id=tenant_id,
            )
        )

        response.headers["X-Process-Time-Ms"] = str(int(process_time))
        return response
