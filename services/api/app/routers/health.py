import time
import logging
from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from app.db import get_db
from app.middleware.auth import validate_api_key
from shared.config import settings
from shared.connectors.llm_provider import get_provider
from shared.connectors.wazuh_api import WazuhAPIConnector
from shared.connectors.wazuh_indexer import WazuhIndexerConnector
from shared.health_registry import HealthRegistry

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])

_registry = HealthRegistry()


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    status = "healthy"
    db_ok = False
    db_latency = 0
    start = time.time()
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
        db_latency = int((time.time() - start) * 1000)
    except Exception:
        status = "degraded"

    redis_ok = False
    redis_latency = 0
    try:
        import redis as _redis
        rstart = time.time()
        r = _redis.from_url(settings.redis_url, decode_responses=True)
        r.ping()
        redis_ok = True
        redis_latency = int((time.time() - rstart) * 1000)
    except Exception as e:
        logger.debug("Redis health check failed: %s", e)

    if not db_ok:
        status = "degraded"

    return {
        "status": status,
        "version": "1.0.0",
        "database": {"connected": db_ok, "latency_ms": db_latency},
        "redis": {"connected": redis_ok, "latency_ms": redis_latency},
        "timestamp": int(time.time()),
    }


@router.get("/health/full")
async def health_check_full(_: str = Depends(validate_api_key)):
    status = await _registry.check_all(use_cache=False)
    return {**status, "timestamp": int(time.time())}


@router.get("/health/ready")
async def readiness():
    return {"ready": True, "timestamp": int(time.time())}


@router.get("/wazuh/health")
async def wazuh_health(_: str = Depends(validate_api_key)):
    api = WazuhAPIConnector()
    indexer = WazuhIndexerConnector()
    api_health = await api.health()
    indexer_health = await indexer.health()
    await api.close()
    await indexer.close()
    return {
        "api_url": api.base_url,
        "api_connected": api_health.get("connected", False),
        "api_details": api_health,
        "indexer_url": indexer.base_url,
        "indexer_connected": indexer_health.get("connected", False),
        "indexer_details": indexer_health,
    }


@router.get("/model/status")
async def model_status(_: str = Depends(validate_api_key)):
    provider = get_provider()
    health = await provider.health()
    return {
        "provider": provider.name(),
        "connected": health.get("connected", False),
        "model": getattr(provider, "model", None),
        "health": health,
    }


@router.get("/metrics")
async def metrics():
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
