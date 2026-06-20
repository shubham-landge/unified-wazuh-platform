"""Asset enricher — queries the assets table for agent criticality and metadata.

Populates EnrichmentContext.asset_criticality from the assets table. A criticality
of 10 combined with a crown-jewel flag triggers the crown-jewel multiplier in
risk_score.

Fail-open: if DB unavailable or no asset record, asset_criticality remains 0.
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.asset import Asset

logger = logging.getLogger(__name__)


async def get_asset_criticality(
    session: AsyncSession,
    agent_id: Optional[str],
    tenant_id: str,
) -> tuple[int, bool]:
    """Look up asset criticality and check if it qualifies as crown-jewel.

    Returns:
        (criticality, is_crown_jewel)
    """
    if not agent_id:
        return 0, False

    try:
        stmt = select(Asset.criticality, Asset.labels).where(
            Asset.agent_id == agent_id,
            Asset.status == "active",
        ).limit(1)
        result = await session.execute(stmt)
        row = result.fetchone()
        if row is None:
            return 0, False

        criticality = int(row.criticality or 0)
        labels = row.labels or {}

        is_crown_jewel = (
            criticality >= 9
            or labels.get("crown_jewel") is True
            or labels.get("classification") == "critical"
        )

        return criticality, is_crown_jewel
    except Exception as exc:
        logger.debug("Asset enricher error for agent %s: %s", agent_id, exc)
        return 0, False


async def get_asset_info(
    session: AsyncSession,
    agent_id: Optional[str],
    tenant_id: str,
) -> Optional[dict]:
    """Return full asset metadata for enrichment context injection.

    Returns None if no asset found or DB error.
    """
    if not agent_id:
        return None

    try:
        stmt = select(Asset).where(
            Asset.agent_id == agent_id,
            Asset.status == "active",
        ).limit(1)
        result = await session.execute(stmt)
        asset = result.scalar_one_or_none()
        if asset is None:
            return None

        return {
            "agent_id": asset.agent_id,
            "agent_name": asset.agent_name,
            "os_platform": asset.os_platform,
            "os_version": asset.os_version,
            "criticality": asset.criticality,
            "owner": asset.owner,
            "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
            "groups": asset.groups,
        }
    except Exception as exc:
        logger.debug("Asset info lookup error for agent %s: %s", agent_id, exc)
        return None
