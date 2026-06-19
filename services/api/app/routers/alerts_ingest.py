"""Webhook / push alert ingestion endpoint.

Accepts pushed alerts from Wazuh integrator or generic sources,
normalizes them through the same pipeline as the poller, and
enqueues them for triage.
"""

import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.status import HTTP_202_ACCEPTED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED

from app.db import get_db
from shared.config import settings
from shared.models.alert import Alert
from services.worker.app.poller import AlertPoller

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts/event", tags=["alerts_ingest"])

# ── Shared resources (lazy) ──────────────────────────────────────────────────

_poller: AlertPoller | None = None
_redis: aioredis.Redis | None = None


def _get_poller() -> AlertPoller:
    global _poller
    if _poller is None:
        _poller = AlertPoller()
    return _poller


async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = await aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


# ── Auth ─────────────────────────────────────────────────────────────────────

api_key_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


async def webhook_auth(
    request: Request,
    api_key: str | None = Depends(api_key_header_scheme),
) -> None:
    """Authenticate via HMAC (X-HMAC-Signature) or API key (X-API-Key).

    Reuses the same hash-comparison logic as :func:`validate_api_key`.
    """
    hmac_sig = request.headers.get("X-HMAC-Signature")

    if hmac_sig:
        body = await request.body()
        for valid_key in settings.api_keys:
            expected = hmac.new(
                valid_key.encode(), body, hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(hmac_sig, expected):
                return
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="Invalid HMAC signature"
        )

    # Fall back to API key
    if not api_key:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key or X-HMAC-Signature",
        )

    incoming_hash = _hash_key(api_key)
    for valid_key in settings.api_keys:
        if hmac.compare_digest(incoming_hash, _hash_key(valid_key)):
            return

    raise HTTPException(
        status_code=HTTP_401_UNAUTHORIZED, detail="Invalid API key"
    )


# ── Payload model ────────────────────────────────────────────────────────────


class WebhookAlertPayload(BaseModel):
    rule_id: int
    rule_description: str
    source: str = Field(..., description="Source label, e.g. 'wazuh_integrator' or 'custom'")
    rule_level: int | None = None
    rule_groups: list[str] | None = None
    agent_id: str | None = None
    agent_name: str | None = None
    agent_ip: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user_name: str | None = None
    process_name: str | None = None
    file_name: str | None = None
    file_hash: str | None = None
    timestamp: str | None = None
    raw_json: dict[str, Any] | None = None


# ── Helper ───────────────────────────────────────────────────────────────────


def _build_wazuh_raw(payload: WebhookAlertPayload) -> dict[str, Any]:
    """Wrap webhook fields into a Wazuh-like alert dict for normalisation."""
    return {
        "id": str(uuid.uuid4()),
        "rule": {
            "id": payload.rule_id,
            "description": payload.rule_description,
            "level": payload.rule_level,
            "groups": payload.rule_groups or [],
        },
        "agent": (
            {
                "id": payload.agent_id,
                "name": payload.agent_name,
                "ip": payload.agent_ip,
            }
            if any([payload.agent_id, payload.agent_name, payload.agent_ip])
            else {}
        ),
        "srcip": payload.source_ip,
        "dstip": payload.destination_ip,
        "data": {
            "user": payload.user_name,
            "process": payload.process_name,
            "file": payload.file_name,
            "hash": payload.file_hash,
        },
        "timestamp": payload.timestamp or datetime.now(timezone.utc).isoformat(),
    }


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", status_code=HTTP_202_ACCEPTED)
@router.post("/{source}", status_code=HTTP_202_ACCEPTED)
async def ingest_alert(
    payload: WebhookAlertPayload,
    request: Request,
    source: str | None = None,
    db: AsyncSession = Depends(get_db),
    _auth_ok: None = Depends(webhook_auth),
) -> dict[str, Any]:
    """Accept a pushed alert, normalise it, persist it, and enqueue for triage.

    Returns ``202 Accepted`` with the generated ``alert_id`` on success.
    """
    if not settings.webhook_ingest_enabled:
        raise HTTPException(status_code=404, detail="Webhook ingestion is disabled")

    manager_label = source or payload.source

    # Wrap into Wazuh-like format and normalise through the poller pipeline
    raw = _build_wazuh_raw(payload)
    poller = _get_poller()
    seen: set[str] = set()

    alert = await poller._normalize_alert(db, raw, manager_label, seen)
    if alert is None:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Alert is duplicate or could not be normalised",
        )

    # Ensure an ID is always set (normalize_alert may leave it None when
    # the raw dict lacks fields the poller expects — webhook wraps guarantee it).
    if not alert.id:
        alert.id = uuid.uuid4()

    db.add(alert)
    await db.flush()

    # Enqueue for triage
    queue_entry = json.dumps(
        {
            "alert_id": str(alert.id),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )

    if settings.queue_backend == "arq":
        try:
            from arq.connections import RedisSettings as ArqRedisSettings, create_pool

            pool = await create_pool(ArqRedisSettings.from_dsn(settings.redis_url))
            try:
                await pool.enqueue_job("triage_job", alert_id=str(alert.id))
            finally:
                await pool.close()
        except Exception:
            logger.exception("ARQ enqueue failed, falling back to legacy queue")
            redis = await _get_redis()
            await redis.lpush("triage_queue", queue_entry)
    else:
        redis = await _get_redis()
        await redis.lpush("triage_queue", queue_entry)

    logger.info(
        "Webhook alert ingested: id=%s source=%s rule_id=%s",
        alert.id,
        manager_label,
        payload.rule_id,
    )

    return {"status": "accepted", "alert_id": str(alert.id)}
