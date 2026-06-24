"""Asset Sync Worker.

Periodically fetches agents from the Wazuh API and upserts them into the
``assets`` table so the platform always has a current view of the agent fleet.

Runs on a timer (configurable via ``ASSET_SYNC_INTERVAL_SECONDS``, default 600).
Designed as a standalone worker for the ``main.py`` loop, not an ARQ cron job,
because a single long-lived HTTP session is more efficient than spawning one per
cron tick.
"""

import asyncio
import logging
from datetime import datetime, timezone

import redis.asyncio as redis
from sqlalchemy import select, update as sa_update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shared.config import settings
from shared.connectors.wazuh_api import WazuhAPIConnector
from shared.models.asset import Asset

logger = logging.getLogger(__name__)


class AssetSyncWorker:
    """Poll the Wazuh API and upsert agents into the assets table."""

    def __init__(self, session_factory=None, redis_client=None):
        self.engine = None
        if session_factory is None:
            self.engine = create_async_engine(settings.database_url, pool_size=2)
            self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        else:
            self.session_factory = session_factory
        self.redis_client = redis_client
        self._stopped = asyncio.Event()

    async def start(self):
        if self.redis_client is None:
            self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        interval = getattr(settings, "asset_sync_interval_seconds", 600)
        logger.info("Asset sync worker started. Interval: %ds", interval)

        while not self._stopped.is_set():
            try:
                await self._sync_once()
            except Exception as exc:
                logger.error("Asset sync failed: %s", exc, exc_info=True)
            try:
                await asyncio.wait_for(
                    self._stopped.wait(), timeout=interval,
                )
            except asyncio.TimeoutError:
                pass

        logger.info("Asset sync worker stopped.")

    async def stop(self):
        self._stopped.set()
        if self.engine:
            await self.engine.dispose()

    # ── Internal ────────────────────────────────────────────────────────────

    async def _sync_once(self) -> int:
        """Fetch all agents from the Wazuh API and upsert into DB.

        Returns the number of upserted / skipped agents.
        """
        api = WazuhAPIConnector()
        try:
            raw_agents = await api.get_agents_summary()
        finally:
            await api.close()

        agents_list = raw_agents.get("data", raw_agents.get("agents", []))
        if not isinstance(agents_list, list):
            logger.warning("Unexpected agent payload shape: %s", type(agents_list))
            return 0

        count = 0
        async with self.session_factory() as session:
            for raw in agents_list:
                agent_id = raw.get("id")
                if not agent_id:
                    continue
                agent_id_str = str(agent_id)

                # Build the DB row from the Wazuh agent payload.
                values = {
                    "agent_name": raw.get("name"),
                    "agent_ip": raw.get("ip"),
                    "os_platform": raw.get("os", {}).get("platform") if isinstance(raw.get("os"), dict) else None,
                    "os_version": raw.get("os", {}).get("version") if isinstance(raw.get("os"), dict) else None,
                    "os_name": raw.get("os", {}).get("name") if isinstance(raw.get("os"), dict) else None,
                    "status": raw.get("status", "active"),
                    "last_seen": _parse_wazuh_datetime(raw.get("lastKeepAlive")),
                    "version": raw.get("version"),
                    "node_name": raw.get("node_name"),
                    "groups": raw.get("groups", []),
                    "updated_at": datetime.now(timezone.utc),
                }

                # Check if the asset exists for this tenant (use first tenant or None).
                # In a multi-tenant setup the tenant_id should come from the API context.
                stmt = select(Asset).where(Asset.agent_id == agent_id_str)
                existing = (await session.execute(stmt)).scalar_one_or_none()

                if existing:
                    for col, val in values.items():
                        setattr(existing, col, val)
                else:
                    asset = Asset(agent_id=agent_id_str, **values)
                    session.add(asset)

                count += 1

            await session.commit()

        logger.info("Asset sync: %d agents upserted", count)
        await self.redis_client.set("asset_sync:last_run", datetime.now(timezone.utc).isoformat())
        return count


def _parse_wazuh_datetime(raw: str | None) -> datetime | None:
    """Parse a Wazuh datetime string like ``2025-06-24T12:34:56Z``."""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = AssetSyncWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
