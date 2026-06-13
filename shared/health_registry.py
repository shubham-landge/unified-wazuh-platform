"""
Health Registry — cached parallel health checks for all platform services.

Usage:
    registry = HealthRegistry()
    status = await registry.check_all()
    status = await registry.check_all(use_cache=True)   # returns cached result within TTL
"""
import asyncio
import logging
import time
from typing import Callable, Awaitable

from shared.config import settings

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 30


class HealthRegistry:
    def __init__(self):
        self._cache: dict | None = None
        self._cache_ts: float = 0.0

    def _checkers(self) -> dict[str, Callable[[], Awaitable[dict]]]:
        from shared.connectors.wazuh_api import WazuhAPIConnector
        from shared.connectors.wazuh_indexer import WazuhIndexerConnector
        from shared.connectors.llm_provider import get_provider
        from shared.connectors.notify_email import EmailConnector
        from shared.connectors.notify_slack import SlackConnector
        from shared.connectors.notify_teams import TeamsConnector
        from shared.connectors.notify_pagerduty import PagerDutyConnector
        from shared.connectors.ti_alienvault import AlienVaultOTXConnector
        from shared.connectors.ti_misp import MISPConnector
        from shared.connectors.ti_virustotal import VirusTotalConnector

        checkers: dict[str, Callable[[], Awaitable[dict]]] = {
            "wazuh_api":     WazuhAPIConnector().health,
            "wazuh_indexer": WazuhIndexerConnector().health,
            "llm_provider":  get_provider().health,
        }

        # Notification connectors — only register if configured
        if settings.smtp_host:
            checkers["smtp"] = EmailConnector().health
        if settings.slack_webhook_url:
            checkers["slack"] = SlackConnector().health
        if settings.teams_webhook_url:
            checkers["teams"] = TeamsConnector().health
        if settings.pagerduty_routing_key:
            checkers["pagerduty"] = PagerDutyConnector().health

        # TI connectors
        if settings.otx_api_key:
            checkers["otx"] = AlienVaultOTXConnector().health
        if settings.misp_url:
            checkers["misp"] = MISPConnector().health
        if settings.virustotal_api_key:
            checkers["virustotal"] = VirusTotalConnector().health

        return checkers

    async def _check_redis(self) -> dict:
        try:
            import redis.asyncio as aioredis
            client = await aioredis.from_url(settings.redis_url, decode_responses=True)
            await client.ping()
            await client.aclose()
            return {"connected": True}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    async def _check_db(self) -> dict:
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
            from sqlalchemy import text
            engine = create_async_engine(settings.database_url)
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            await engine.dispose()
            return {"connected": True}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    async def check_all(self, use_cache: bool = False) -> dict:
        now = time.monotonic()
        if use_cache and self._cache and (now - self._cache_ts) < _CACHE_TTL_SECONDS:
            return self._cache

        checkers = self._checkers()
        checkers["redis"] = self._check_redis
        checkers["database"] = self._check_db

        # Run all checks in parallel with individual timeouts
        async def _safe_check(name: str, fn: Callable) -> tuple[str, dict]:
            try:
                result = await asyncio.wait_for(fn(), timeout=10.0)
                return name, result
            except asyncio.TimeoutError:
                return name, {"connected": False, "error": "timeout"}
            except Exception as e:
                return name, {"connected": False, "error": str(e)}

        tasks = [_safe_check(name, fn) for name, fn in checkers.items()]
        results = await asyncio.gather(*tasks)

        services = dict(results)
        healthy = sum(1 for v in services.values() if v.get("connected", False))
        total = len(services)

        aggregate = {
            "status": "healthy" if healthy == total else ("degraded" if healthy > 0 else "unhealthy"),
            "healthy": healthy,
            "total": total,
            "services": services,
        }

        self._cache = aggregate
        self._cache_ts = now
        return aggregate
