import asyncio
import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from shared.config import settings
from shared.models.feedback import UserFeedback
from shared.models.ai_triage_result import AiTriageResult
from shared.connectors.llm_provider import get_provider

logger = logging.getLogger(__name__)

class PromptRefiner:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def start(self):
        while True:
            try:
                await self.refine_loop()
            except Exception as e:
                logger.error("Prompt refiner error: %s", e)
            await asyncio.sleep(60)

    async def refine_loop(self):
        async with self.session_factory() as session:
            stmt = select(UserFeedback).where(UserFeedback.rating <= 2)
            res = await session.execute(stmt)
            feedbacks = res.scalars().all()
            if not feedbacks:
                return

            for fb in feedbacks:
                triage_stmt = select(AiTriageResult).where(AiTriageResult.id == fb.triage_result_id)
                triage_res = await session.execute(triage_stmt)
                triage = triage_res.scalar_one_or_none()
                if triage:
                    await self._refine_prompt(triage, fb)

    async def _refine_prompt(self, triage: AiTriageResult, feedback: UserFeedback):
        provider = get_provider()
        sys_prompt = "You are a prompt engineer. Propose a prompt edit based on the mistake."
        user_prompt = f"Original Prompt: {triage.prompt_text}\nMistake: {feedback.correction_text}\nResponse: {triage.response_text}"
        res = await provider.analyze(system_prompt=sys_prompt, user_prompt=user_prompt)
        refined = res.get("summary")
        if refined:
            import os
            os.makedirs("prompts", exist_ok=True)
            with open("prompts/best_skill.md", "w") as f:
                f.write(refined)

    async def stop(self):
        await self.engine.dispose()
