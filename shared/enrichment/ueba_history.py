"""UEBA history enricher — queries historical anomalies for the alert's entities.

Beyond the real-time z-score from the current alert, this enricher looks up
historical UEBA anomalies for the agent, user, and IP entities associated with
the alert. This provides context about whether the entity has been repeatedly
anomalous — a signal that the real-time z-score alone may miss.

Fail-open: if DB unavailable, returns empty list and 0.0 max_score.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.ueba import UebaAnomaly

logger = logging.getLogger(__name__)

# Look-back window for historical anomalies (days)
_DEFAULT_LOOKBACK_DAYS = 30


async def get_entity_history(
    session: AsyncSession,
    agent_id: Optional[str],
    user_name: Optional[str],
    source_ip: Optional[str],
    tenant_id: str,
    lookback_days: int = _DEFAULT_LOOKBACK_DAYS,
) -> tuple[list[dict], float]:
    """Retrieve historical UEBA anomalies for the alert's entities.

    Args:
        session: Async DB session.
        agent_id: Agent ID from the alert.
        user_name: Username from the alert.
        source_ip: Source IP from the alert.
        tenant_id: Tenant scope.
        lookback_days: How many days back to look for historical anomalies.

    Returns:
        (anomalies, max_historical_zscore)
    """
    if not any([agent_id, user_name, source_ip]):
        return [], 0.0

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

        # Build OR-filter conditions for entity matching
        from sqlalchemy import or_

        entity_filters = []
        if agent_id:
            entity_filters.append(
                (UebaAnomaly.subject_type == "agent")
                & (UebaAnomaly.subject_id == agent_id)
            )
        if user_name:
            entity_filters.append(
                (UebaAnomaly.subject_type == "user")
                & (UebaAnomaly.subject_id == user_name)
            )
        if source_ip:
            entity_filters.append(
                (UebaAnomaly.subject_type == "source_ip")
                & (UebaAnomaly.subject_id == source_ip)
            )

        if not entity_filters:
            return [], 0.0

        stmt = (
            select(UebaAnomaly)
            .where(
                or_(*entity_filters),
                UebaAnomaly.detected_at >= cutoff,
                UebaAnomaly.status != "resolved",
            )
            .order_by(desc(UebaAnomaly.score))
            .limit(20)
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()

        max_zscore = 0.0
        anomalies = []
        for row in rows:
            z = float(row.score or 0.0)
            if z > max_zscore:
                max_zscore = z
            anomalies.append({
                "anomaly_id": str(row.id),
                "subject_type": row.subject_type,
                "subject_id": row.subject_id,
                "anomaly_type": row.anomaly_type,
                "z_score": z,
                "severity": row.severity,
                "description": row.description,
                "detected_at": row.detected_at.isoformat() if row.detected_at else None,
            })

        return anomalies, max_zscore
    except Exception as exc:
        logger.debug("UEBA history enricher error: %s", exc)
        return [], 0.0


async def count_anomalies(
    session: AsyncSession,
    agent_id: Optional[str],
    user_name: Optional[str],
    source_ip: Optional[str],
    tenant_id: str,
    lookback_days: int = _DEFAULT_LOOKBACK_DAYS,
) -> int:
    """Quick count of historical anomalies for given entities."""
    if not any([agent_id, user_name, source_ip]):
        return 0

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        from sqlalchemy import or_

        entity_filters = []
        if agent_id:
            entity_filters.append(
                (UebaAnomaly.subject_type == "agent")
                & (UebaAnomaly.subject_id == agent_id)
            )
        if user_name:
            entity_filters.append(
                (UebaAnomaly.subject_type == "user")
                & (UebaAnomaly.subject_id == user_name)
            )
        if source_ip:
            entity_filters.append(
                (UebaAnomaly.subject_type == "source_ip")
                & (UebaAnomaly.subject_id == source_ip)
            )

        if not entity_filters:
            return 0

        stmt = select(func.count()).select_from(UebaAnomaly).where(
            or_(*entity_filters),
            UebaAnomaly.detected_at >= cutoff,
        )
        result = await session.execute(stmt)
        return result.scalar() or 0
    except Exception as exc:
        logger.debug("UEBA history count error: %s", exc)
        return 0
