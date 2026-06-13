import asyncio
import json
import logging

import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shared.config import settings
from shared.connectors.osint_maigret import MaigretConnector
from shared.models.osint import OsintResult, OsintTarget

logger = logging.getLogger(__name__)


class OSINTWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client: redis.Redis | None = None

    async def start(self):
        self.redis_client = redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("OSINT worker started. Waiting for lookup jobs...")

        while True:
            try:
                item = await self.redis_client.brpop("osint_queue", timeout=5)
                if item:
                    _, msg = item
                    await self.process_message(json.loads(msg))
            except TypeError:
                continue
            except Exception as exc:
                logger.error("OSINT worker error: %s", exc, exc_info=True)
                await asyncio.sleep(1)

    async def process_message(self, msg: dict):
        target_id = msg.get("target_id")
        if not target_id:
            return

        try:
            async with self.session_factory() as session:
                result = await session.execute(select(OsintTarget).where(OsintTarget.id == target_id))
                target = result.scalar_one_or_none()
                if not target:
                    logger.warning("OSINT target %s not found", target_id)
                    return

                connector = MaigretConnector()
                lookup_value = target.target_value
                results = await asyncio.wait_for(
                    connector.lookup_username(lookup_value),
                    timeout=settings.osint_sandbox_timeout,
                )

                for item in results:
                    session.add(
                        OsintResult(
                            target_id=target.id,
                            source=item.get("source") or "unknown",
                            profile_url=item.get("profile_url"),
                            name=item.get("name"),
                            location=item.get("location"),
                            raw_data=item.get("raw_data") or item,
                        )
                    )

                await session.commit()
                logger.info("Enriched OSINT target %s with %d results", target_id, len(results))
        except Exception as exc:
            logger.error("Failed to process OSINT target %s: %s", target_id, exc, exc_info=True)
            if self.redis_client:
                await self.redis_client.lpush(
                    "osint_dlq",
                    json.dumps({"target_id": target_id, "error": str(exc)}),
                )

    async def stop(self):
        if self.redis_client:
            await self.redis_client.close()
        await self.engine.dispose()
