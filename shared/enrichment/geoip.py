"""GeoIP enrichment stub — degrades gracefully when unavailable.

In production this would call a local MaxMind GeoLite2 database or a remote
geo-IP service. The stub returns a minimal placeholder so callers never crash.
"""

import logging

logger = logging.getLogger(__name__)


async def lookup(ip: str) -> dict | None:
    """Look up GeoIP data for an IP address.

    Returns None when disabled or unavailable — callers must handle gracefully.
    """
    logger.debug("GeoIP lookup requested for %s (stub — returning None)", ip)
    return None
