import asyncio
import json
import logging
import uuid

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings
from shared.orchestrator.engine import OrchestrationEngine

logger = logging.getLogger(__name__)


class AgentWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client: redis.Redis | None = None
        self.orchestrator = OrchestrationEngine(session_factory=self.session_factory)

    async def start(self):
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("Agent worker started. Waiting for jobs...")

        while True:
            try:
                item = await self.redis_client.brpop("agent_queue", timeout=5)
                if item:
                    _, msg = item
                    payload = json.loads(msg)
                    run_id = payload.get("run_id")
                    if run_id:
                        await self.orchestrator.execute_run(uuid.UUID(run_id))
            except TypeError:
                continue
            except Exception as exc:
                logger.error("Agent worker error: %s", exc, exc_info=True)
                await asyncio.sleep(1)

    async def stop(self):
        if self.redis_client:
            await self.redis_client.close()
        await self.engine.dispose()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = AgentWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
