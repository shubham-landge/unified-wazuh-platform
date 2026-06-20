"""Threat intelligence enricher — queries IOC database for known-bad indicators.

Looks up the alert's source IP against the threat_intel_iocs table to determine
whether the indicator is a known-bad. Returns confidence and KEV status.

Fail-open: if DB unavailable or no match, returns (False, 0.0, False).
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.threat_intel import ThreatIntelIoc

logger = logging.getLogger(__name__)


async def lookup(
    session: AsyncSession,
    source_ip: Optional[str],
    tenant_id: str,
) -> tuple[bool, float, bool]:
    """Check if source_ip is a known-bad IOC in the database.

    Returns:
        (is_known_bad, confidence, is_kev)
    """
    if not source_ip:
        return False, 0.0, False

    try:
        stmt = (
            select(
                ThreatIntelIoc.threat_score,
                ThreatIntelIoc.confidence,
                ThreatIntelIoc.tags,
            )
            .where(
                ThreatIntelIoc.ioc_type == "ip",
                ThreatIntelIoc.ioc_value == source_ip,
                ThreatIntelIoc.is_active.is_(True),
            )
            .limit(1)
        )
        result = await session.execute(stmt)
        row = result.fetchone()
        if row is None:
            return False, 0.0, False

        threat_score = float(row.threat_score or 0.0)
        confidence = float(row.confidence or 0.0)
        tags = row.tags or []

        is_known_bad = threat_score >= 50.0 or confidence >= 0.8
        is_kev = any("kev" in str(t).lower() for t in tags)

        return is_known_bad, confidence, is_kev
    except Exception as exc:
        logger.debug("TI enricher error for IP %s: %s", source_ip, exc)
        return False, 0.0, False


async def is_ip_known_bad(
    session: AsyncSession,
    source_ip: Optional[str],
    tenant_id: str,
) -> bool:
    """Quick boolean check — is this IP a known-bad IOC?"""
    is_bad, _, _ = await lookup(session, source_ip, tenant_id)
    return is_bad
