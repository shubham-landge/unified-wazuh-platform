"""Wazuh Environment Health API.

Exposes the latest snapshot and recent history captured by the
wazuh_health_worker. This is the overlay's view of Wazuh's own health — agent
connectivity, manager/cluster, indexer/ingestion, and our pipeline SLAs.
"""
import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from shared.models.wazuh_health import WazuhHealthSnapshot

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/wazuh", tags=["wazuh-health"])


def _serialize(s: WazuhHealthSnapshot) -> dict:
    return {
        "captured_at": s.captured_at.isoformat() if s.captured_at else None,
        "manager_label": s.manager_label,
        "overall_status": s.overall_status,
        "issues": s.issues,
        "agents": {
            "active": s.agents_active,
            "disconnected": s.agents_disconnected,
            "never_connected": s.agents_never_connected,
            "pending": s.agents_pending,
            "total": s.agents_total,
        },
        "manager": {
            "cluster_status": s.cluster_status,
            "all_running": s.manager_all_running,
            "analysisd_eps": s.analysisd_eps,
            "analysisd_queue_pct": s.analysisd_queue_pct,
            "events_dropped": s.events_dropped,
        },
        "indexer": {
            "status": s.indexer_status,
            "unassigned_shards": s.indexer_unassigned_shards,
            "ingestion_lag_seconds": s.ingestion_lag_seconds,
        },
        "self": {
            "poller_lag_seconds": s.self_poller_lag_seconds,
            "triage_queue_depth": s.self_triage_queue_depth,
        },
    }


@router.get("/environment")
async def get_environment(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    """Latest Wazuh environment health snapshot."""
    result = await db.execute(
        select(WazuhHealthSnapshot).order_by(desc(WazuhHealthSnapshot.captured_at)).limit(1)
    )
    snap = result.scalar_one_or_none()
    if not snap:
        return {"status": "no_data", "snapshot": None}
    return {"status": "success", "snapshot": _serialize(snap)}


@router.get("/environment/history")
async def get_environment_history(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    """Recent Wazuh environment snapshots (newest first)."""
    result = await db.execute(
        select(WazuhHealthSnapshot).order_by(desc(WazuhHealthSnapshot.captured_at)).limit(limit)
    )
    snaps = result.scalars().all()
    return {"status": "success", "count": len(snaps), "snapshots": [_serialize(s) for s in snaps]}
