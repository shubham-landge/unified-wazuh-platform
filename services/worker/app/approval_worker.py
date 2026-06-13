import asyncio
import json
import logging
from datetime import datetime, timezone
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select, update

from shared.config import settings
from shared.models.approval import ApprovalRequest

logger = logging.getLogger(__name__)

class ApprovalWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client = None
        self.running = False
        self.tasks = []

    async def start(self):
        self.running = True
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        self.tasks.append(asyncio.create_task(self.run_expiry_loop()))
        self.tasks.append(asyncio.create_task(self.run_queue_consumer()))
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def stop(self):
        self.running = False
        for t in self.tasks:
            t.cancel()
        if self.redis_client:
            await self.redis_client.close()
        await self.engine.dispose()

    async def run_expiry_loop(self):
        while self.running:
            try:
                await self.check_expired_approvals()
            except Exception as e:
                logger.error("Error checking expired approvals: %s", e)
            await asyncio.sleep(60)

    async def check_expired_approvals(self):
        async with self.session_factory() as session:
            now = datetime.now(timezone.utc)
            query = (
                update(ApprovalRequest)
                .where(ApprovalRequest.status == "pending")
                .where(ApprovalRequest.expires_at <= now)
                .values(status="expired", updated_at=now)
            )
            await session.execute(query)
            await session.commit()

    async def run_queue_consumer(self):
        while self.running:
            try:
                item = await self.redis_client.brpop("approval_execute_queue", timeout=5)
                if item:
                    _, msg = item
                    await self.execute_approved_action(json.loads(msg))
            except TypeError:
                continue
            except Exception as e:
                logger.error("Error in approval queue consumer: %s", e)
                await asyncio.sleep(1)

    async def execute_approved_action(self, msg: dict):
        approval_id = msg.get("approval_id")
        if not approval_id:
            return
        async with self.session_factory() as session:
            res = await session.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
            req = res.scalar_one_or_none()
            if not req or req.status != "approved":
                return
            logger.info("Executing approved action %s for %s", req.action_type, req.target_ref)
