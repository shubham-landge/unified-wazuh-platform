import time
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from shared.health_registry import HealthRegistry

router = APIRouter(tags=["health"])

# Module-level registry so the cache persists across requests
_registry = HealthRegistry()


@router.get("/health")
async def health_check(_: str = Depends(validate_api_key)):
    """Cached parallel health check across all platform services."""
    status = await _registry.check_all(use_cache=True)
    return {**status, "timestamp": int(time.time())}


@router.get("/health/full")
async def health_check_full(_: str = Depends(validate_api_key)):
    """Force-refresh health check (bypasses cache)."""
    status = await _registry.check_all(use_cache=False)
    return {**status, "timestamp": int(time.time())}


@router.get("/health/ready")
async def readiness():
    """Lightweight readiness probe — no auth, no external calls."""
    return {"ready": True, "timestamp": int(time.time())}
