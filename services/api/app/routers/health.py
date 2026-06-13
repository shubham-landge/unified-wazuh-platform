import time
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.db import get_db
from app.middleware.auth import validate_api_key
from shared.connectors.llm_provider import get_provider
from shared.connectors.wazuh_api import WazuhAPIConnector
from shared.connectors.wazuh_indexer import WazuhIndexerConnector

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db), _: str = Depends(validate_api_key)):
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

    return {
        "status": status,
        "version": "1.0.0",
        "database": {
            "connected": db_ok,
            "latency_ms": db_latency,
        },
        "timestamp": int(time.time()),
    }


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
