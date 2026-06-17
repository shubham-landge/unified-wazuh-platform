import asyncio
import logging
import os
import shutil
from collections import defaultdict
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings
from shared.models.feedback import UserFeedback
from shared.models.ai_triage_result import AiTriageResult
from shared.connectors.llm_provider import get_provider

logger = logging.getLogger(__name__)

ARCHIVE_DIR = "prompts/archive"
BEST_SKILL_PATH = "prompts/best_skill.md"
MIN_PROMPT_LENGTH = 50
REQUIRED_SECTIONS = ["# Detection Logic", "# Investigation Steps"]
PROMPT_SIMILARITY_THRESHOLD = 0.6


class PromptRefiner:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self._stopped = asyncio.Event()
        os.makedirs(ARCHIVE_DIR, exist_ok=True)

    async def start(self):
        while not self._stopped.is_set():
            try:
                await self.refine_loop()
            except Exception as e:
                logger.error("Prompt refiner error: %s", e, exc_info=True)
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass

    async def stop(self):
        self._stopped.set()
        await self.engine.dispose()

    async def refine_loop(self):
        async with self.session_factory() as session:
            stmt = (
                select(UserFeedback)
                .where(UserFeedback.rating <= 2, UserFeedback.rating > 0)
                .order_by(UserFeedback.created_at.desc())
                .limit(50)
            )
            res = await session.execute(stmt)
            feedbacks = list(res.scalars().all())
            if not feedbacks:
                return

            clusters = self._cluster_feedback(feedbacks)
            logger.info("Prompt refiner: %d feedback items in %d clusters", len(feedbacks), len(clusters))

            for cluster_key, fb_group in clusters.items():
                triages = []
                for fb in fb_group:
                    triage_stmt = select(AiTriageResult).where(AiTriageResult.id == fb.triage_result_id)
                    triage_res = await session.execute(triage_stmt)
                    triage = triage_res.scalar_one_or_none()
                    if triage:
                        triages.append((triage, fb))

                if not triages:
                    continue

                refined = await self._generate_refined_prompt(triages)
                if not refined:
                    continue

                approved, reason = await self._shadow_evaluate(refined, cluster_key, triages)
                if not approved:
                    logger.info("Prompt refiner: rejected refinement for cluster '%s': %s", cluster_key[:50], reason)
                    continue

                self._archive_current()
                self._write_prompt(refined)
                for _, fb in triages:
                    fb.rating = 0

                logger.info("Prompt refiner: promoted refinement for cluster '%s'", cluster_key[:50])

            await session.commit()

    def _cluster_feedback(self, feedbacks):
        clusters = defaultdict(list)
        for fb in feedbacks:
            text = (fb.correction_text or "").strip().lower()
            if not text:
                clusters["unknown"].append(fb)
                continue
            if "category" in text or "misclassif" in text:
                clusters["misclassification"].append(fb)
            elif "confidence" in text or "overconf" in text or "uncertain" in text:
                clusters["confidence"].append(fb)
            elif "miss" in text or "false negative" in text or "missed" in text:
                clusters["false_negative"].append(fb)
            elif "noise" in text or "false positive" in text or "benign" in text:
                clusters["false_positive"].append(fb)
            elif "format" in text or "json" in text or "parse" in text:
                clusters["format_error"].append(fb)
            else:
                clusters[text[:60]].append(fb)
        return dict(clusters)

    async def _generate_refined_prompt(self, triages):
        provider = get_provider()
        sys_prompt = (
            "You are a SOC prompt engineer. Based on the following triage mistakes, "
            "propose an improved version of the prompt template. The refined prompt must:\n"
            "1. Include '# Detection Logic' and '# Investigation Steps' sections\n"
            "2. Be at least 50 characters long\n"
            "3. Fix the specific mistakes shown in the feedback\n"
            "4. Return ONLY the new prompt, no commentary"
        )
        samples = []
        for triage, fb in triages[:5]:
            prompt_text = triage.prompt_text or "[no prompt]"
            correction = fb.correction_text or "[no correction]"
            response_text = triage.response_text or "[no response]"
            samples.append(
                f"Prompt: {prompt_text[:500]}\n"
                f"Mistake: {correction}\n"
                f"Response: {response_text[:300]}"
            )
        user_prompt = "\n---\n".join(samples)
        res = await provider.analyze(system_prompt=sys_prompt, user_prompt=user_prompt)
        return (res.get("summary") or "").strip()

    async def _shadow_evaluate(self, refined_prompt, cluster_key, triages):
        if not refined_prompt or len(refined_prompt) < MIN_PROMPT_LENGTH:
            return False, "too short"

        sections_found = sum(1 for sec in REQUIRED_SECTIONS if sec.lower() in refined_prompt.lower())
        if sections_found < len(REQUIRED_SECTIONS):
            return False, f"missing required sections (found {sections_found}/{len(REQUIRED_SECTIONS)})"

        if os.path.exists(BEST_SKILL_PATH):
            with open(BEST_SKILL_PATH) as f:
                current = f.read()
            if len(refined_prompt) < len(current) * 0.3:
                return False, "refined prompt too short vs current"

            overlap = len(set(refined_prompt.lower().split()) & set(current.lower().split()))
            total = max(len(set(refined_prompt.lower().split())), 1)
            similarity = overlap / total
            if similarity > PROMPT_SIMILARITY_THRESHOLD:
                logger.info("Prompt refiner: refinement too similar to current (%.2f), skipping", similarity)
                return False, f"too similar to current ({similarity:.2f})"

        return True, ""

    def _archive_current(self):
        if not os.path.exists(BEST_SKILL_PATH):
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = f"best_skill_{ts}.md"
        shutil.copy2(BEST_SKILL_PATH, os.path.join(ARCHIVE_DIR, archive_name))
        logger.info("Prompt refiner: archived current prompt -> %s", archive_name)

    def _write_prompt(self, content):
        os.makedirs("prompts", exist_ok=True)
        with open(BEST_SKILL_PATH, "w") as f:
            f.write(content)
        logger.info("Prompt refiner: wrote refined prompt to %s", BEST_SKILL_PATH)
