import asyncio
import json
import logging
from collections import defaultdict

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select, func

from shared.config import settings
from shared.models.feedback import UserFeedback

logger = logging.getLogger(__name__)


class FeedbackWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client: redis.Redis | None = None

        self.model_accuracy: dict[str, list[int]] = defaultdict(list)
        self.category_accuracy: dict[str, list[bool]] = defaultdict(list)

    async def start(self):
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("Feedback worker started. Waiting for feedback...")

        while True:
            try:
                item = await self.redis_client.brpop("feedback_queue", timeout=5)
                if item:
                    _, msg = item
                    await self.process_message(json.loads(msg))
            except TypeError:
                continue
            except Exception as e:
                logger.error("Feedback worker error: %s", e, exc_info=True)
                await asyncio.sleep(1)

    async def process_message(self, msg: dict):
        feedback_id = msg.get("feedback_id")
        triage_result_id = msg.get("triage_result_id")
        rating = msg.get("rating")

        if not feedback_id or not triage_result_id:
            return

        logger.info("Processing feedback %s (rating=%d)", feedback_id, rating)

        try:
            async with self.session_factory() as session:
                result = await session.execute(
                    select(UserFeedback).where(UserFeedback.id == feedback_id)
                )
                feedback = result.scalar_one_or_none()
                if not feedback:
                    logger.warning("Feedback %s not found", feedback_id)
                    return

                model_name = None
                try:
                    from shared.models.ai_triage_result import AiTriageResult
                    triage_result = await session.execute(
                        select(AiTriageResult).where(AiTriageResult.id == feedback.triage_result_id)
                    )
                    triage = triage_result.scalar_one_or_none()
                    if triage:
                        model_name = triage.model_name
                except Exception:
                    pass

                if model_name:
                    self.model_accuracy[model_name].append(rating)

                if feedback.category_correct is not None:
                    key = f"{model_name or 'unknown'}:category"
                    self.category_accuracy[key].append(feedback.category_correct)

                logger.info(
                    "Feedback %s processed. Model=%s Rating=%d CategoryCorrect=%s",
                    feedback_id, model_name or "N/A", rating, feedback.category_correct,
                )

            await self._log_metrics()

        except Exception as e:
            logger.error("Failed to process feedback %s: %s", feedback_id, e, exc_info=True)

    async def _log_metrics(self):
        if not self.model_accuracy:
            return
        async with self.session_factory() as session:
            try:
                from shared.models.model_run import ModelRun
                for model, ratings in self.model_accuracy.items():
                    avg = sum(ratings) / len(ratings)
                    logger.info("Persisting accuracy for [%s]: avg=%.2f count=%d", model, avg, len(ratings))
                    model_run = ModelRun(
                        model_name=model,
                        accuracy=round(avg, 2),
                        total_feedback=len(ratings),
                        success=True,
                    )
                    session.add(model_run)
                await session.commit()
            except Exception as e:
                logger.error("Failed to persist model metrics: %s", e, exc_info=True)

    async def stop(self):
        if self.redis_client:
            await self.redis_client.close()
        await self.engine.dispose()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = FeedbackWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
