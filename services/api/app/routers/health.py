from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.db import get_db
from app.middleware.auth import validate_api_key

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db), _: str = Depends(validate_api_key)):
    status = "healthy"
    db_ok = False
    db_latency = 0

    import time
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
    from app.config import settings

    checks = {
        "api_url": settings.wazuh_api_url,
        "api_connected": False,
        "indexer_url": settings.wazuh_indexer_url,
        "indexer_connected": False,
    }
    return checks


@router.get("/model/status")
async def model_status(_: str = Depends(validate_api_key)):
    from app.config import settings

    return {
        "provider": settings.llm_provider,
        "model": settings.ollama_model,
        "fast_model": settings.ollama_fast_model,
        "connected": False,
        "last_check": None,
    }
