"""Watchlist hit-check stub — degrades gracefully when unavailable.

In production this would check alert IOCs (IPs, domains, hashes) against
curated threat watchlists. The stub returns an empty list so callers never crash.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.alert import Alert

logger = logging.getLogger(__name__)


async def check(session: AsyncSession, alert: Alert) -> list[dict]:
    """Check alert entities against configured watchlists.

    Returns an empty list when disabled or unavailable.
    """
    logger.debug(
        "Watchlist check requested for alert %s (stub — returning [])",
        alert.id,
    )
    return []
