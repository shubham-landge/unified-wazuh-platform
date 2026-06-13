import asyncio
import json
import logging
from datetime import datetime, timezone

import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings
from shared.models.ticketing import TicketingConfig, TicketLink
from shared.connectors.ticket_servicenow import ServiceNowConnector
from shared.connectors.ticket_jira import JiraConnector
from shared.models.case import Case

logger = logging.getLogger(__name__)

POLL_INTERVAL = 300


class TicketingWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client: redis.Redis | None = None
        self._connector_cache: dict[str, ServiceNowConnector | JiraConnector] = {}

    async def start(self):
        if not settings.ticketing_sync_enabled:
            logger.info("Ticketing sync disabled. Skipping.")
            return

        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("Ticketing worker started. Polling every %ds...", POLL_INTERVAL)

        while True:
            try:
                await self._sync_cycle()
            except Exception as e:
                logger.error("Ticketing sync cycle failed: %s", e, exc_info=True)
            await asyncio.sleep(POLL_INTERVAL)

    async def _sync_cycle(self):
        async with self.session_factory() as session:
            configs = await self._load_active_configs(session)
            if not configs:
                return

            result = await session.execute(
                select(Case).where(Case.status.in_(["open", "in_progress", "resolved"]))
            )
            cases = result.scalars().all()

            for case in cases:
                for cfg in configs:
                    connector = self._get_connector(cfg.provider, cfg.config)
                    if not connector:
                        continue

                    existing = await session.execute(
                        select(TicketLink).where(
                            TicketLink.case_id == case.id,
                            TicketLink.provider == cfg.provider,
                        )
                    )
                    link = existing.scalar_one_or_none()

                    case_data = {
                        "title": str(case.title),
                        "description": str(case.description or ""),
                        "severity": str(case.severity or "low"),
                        "status": str(case.status or "open"),
                        "assigned_to": str(case.assigned_to or ""),
                    }

                    if link:
                        result = await connector.update_ticket(link.remote_ticket_id, case_data)
                    else:
                        result = await connector.create_ticket(case_data)
                        if result.get("success"):
                            link = TicketLink(
                                case_id=case.id,
                                provider=cfg.provider,
                                remote_ticket_id=result["remote_id"],
                                remote_ticket_url=result.get("remote_url", ""),
                                sync_status="synced",
                                last_synced_at=datetime.now(timezone.utc),
                            )
                            session.add(link)

                    if link:
                        link.sync_status = "synced" if result.get("success") else "error"
                        link.last_synced_at = datetime.now(timezone.utc)

            await session.commit()

    async def _load_active_configs(self, session):
        result = await session.execute(
            select(TicketingConfig).where(TicketingConfig.is_active == True)
        )
        return result.scalars().all()

    def _get_connector(self, provider: str, config: dict):
        key = f"{provider}:{json.dumps(config, sort_keys=True)}"
        if key in self._connector_cache:
            return self._connector_cache[key]

        provider = provider.lower()
        if provider == "servicenow":
            conn = ServiceNowConnector(
                instance=config.get("instance"),
                user=config.get("user"),
                password=config.get("password"),
            )
        elif provider == "jira":
            conn = JiraConnector(
                url=config.get("url"),
                email=config.get("email"),
                api_token=config.get("api_token"),
            )
        else:
            logger.warning("Unknown ticketing provider: %s", provider)
            return None

        self._connector_cache[key] = conn
        return conn

    async def stop(self):
        if self.redis_client:
            await self.redis_client.close()
        await self.engine.dispose()
