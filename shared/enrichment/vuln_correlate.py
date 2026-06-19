"""Vulnerability correlation stub — degrades gracefully when unavailable.

In production this would cross-reference the alert's agent OS/software against
known CVEs. The stub returns an empty list so callers never crash.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.alert import Alert

logger = logging.getLogger(__name__)


async def correlate(session: AsyncSession, alert: Alert) -> list[dict]:
    """Correlate the alert against known vulnerabilities for the affected host.

    Returns an empty list when disabled or unavailable.
    """
    logger.debug(
        "Vuln correlation requested for alert %s, agent %s (stub — returning [])",
        alert.id,
        alert.agent_id,
    )
    return []
