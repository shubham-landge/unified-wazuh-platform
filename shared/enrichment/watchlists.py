"""Tenant-scoped watchlist enricher.

Allowlists: IP/hostname/user entries that force risk score → 0 (safe).
Blocklists: Known-bad indicators that add risk.
Crown-jewels: High-criticality asset tags (force asset_criticality=10).

Backend: Redis SSET per tenant. Keys:
  wl:{tenant_id}:allowlist
  wl:{tenant_id}:blocklist
  wl:{tenant_id}:crown_jewels

Fall-back: if Redis unavailable, all lookups return False (fail-open).
"""
from __future__ import annotations
import logging
from typing import Optional
logger = logging.getLogger(__name__)

class WatchlistCache:
    def __init__(self, redis_client=None):
        self._r = redis_client
    
    def _key(self, tenant_id: str, list_name: str) -> str:
        return f"wl:{tenant_id}:{list_name}"
    
    def is_allowlisted(self, tenant_id: str, indicators: list[str]) -> bool:
        """Check any indicator (IP, user, hostname) against tenant allowlist."""
        if not self._r or not indicators:
            return False
        try:
            key = self._key(tenant_id, "allowlist")
            return any(self._r.sismember(key, ind) for ind in indicators if ind)
        except Exception as e:
            logger.debug("watchlist allowlist error: %s", e)
            return False
    
    def is_blocklisted(self, tenant_id: str, indicators: list[str]) -> tuple[bool, float]:
        """Check blocklist. Returns (hit, confidence)."""
        if not self._r or not indicators:
            return False, 0.0
        try:
            key = self._key(tenant_id, "blocklist")
            for ind in indicators:
                if ind and self._r.sismember(key, ind):
                    return True, 0.9
            return False, 0.0
        except Exception as e:
            logger.debug("watchlist blocklist error: %s", e)
            return False, 0.0
    
    def is_crown_jewel(self, tenant_id: str, asset_indicators: list[str]) -> bool:
        """Check if any asset indicator is tagged as crown-jewel."""
        if not self._r or not asset_indicators:
            return False
        try:
            key = self._key(tenant_id, "crown_jewels")
            return any(self._r.sismember(key, a) for a in asset_indicators if a)
        except Exception as e:
            logger.debug("watchlist crown_jewel error: %s", e)
            return False
    
    def add_to_list(self, tenant_id: str, list_name: str, indicator: str, ttl: int = 86400 * 30):
        """Add an indicator to a list (API-callable)."""
        if not self._r:
            return
        try:
            key = self._key(tenant_id, list_name)
            self._r.sadd(key, indicator)
            self._r.expire(key, ttl)
        except Exception as e:
            logger.warning("watchlist add failed: %s", e)
    
    def remove_from_list(self, tenant_id: str, list_name: str, indicator: str):
        if not self._r:
            return
        try:
            self._r.srem(self._key(tenant_id, list_name), indicator)
        except Exception as e:
            logger.warning("watchlist remove failed: %s", e)
