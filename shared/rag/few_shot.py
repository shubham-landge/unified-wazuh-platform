"""Few-shot example retrieval from skill memory.

Provides the ``retrieve(agent_type, input_data)`` function that returns
top-K similar past tasks from the skill memory store. This is the shared
contract consumed by agent handlers in the orchestration layer.

Antigravity zone — owned by Antigravity.
"""

import json
import logging

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings as s
from shared.models.agent import AgentTask

logger = logging.getLogger(__name__)


_SKILL_CACHE = {}

async def load_skill(technique_id: str) -> str:
    if not technique_id:
        return ""
    if technique_id in _SKILL_CACHE:
        return _SKILL_CACHE[technique_id]
    import os
    path = os.path.join("prompts", "skills", f"{technique_id}.md")
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        parts = content.split("---")
        body = parts[-1].strip() if len(parts) >= 3 else content.strip()
        _SKILL_CACHE[technique_id] = body
        return body
    except Exception:
        return ""

async def retrieve(agent_type: str, input_data: dict, top_k: int = 5, technique_ids: list[str] | None = None) -> list[dict]:
    if not s.rag_skill_memory_enabled:
        return []

    try:
        examples = []
        if technique_ids:
            for tid in technique_ids:
                body = await load_skill(tid)
                if body:
                    examples.append({
                        "type": "skill",
                        "technique": tid,
                        "content": body
                    })

        try:
            engine = create_async_engine(s.database_url, pool_size=1)
            session_factory = async_sessionmaker(engine, expire_on_commit=False)

            async with session_factory() as session:
                result = await session.execute(
                    select(AgentTask)
                    .where(AgentTask.agent_type == agent_type, AgentTask.status == "completed")
                    .order_by(desc(AgentTask.completed_at))
                    .limit(top_k)
                )
                tasks = result.scalars().all()

                for t in tasks:
                    inp = t.input_data or {}
                    out = t.output_data or {}
                    examples.append({
                        "input_data": inp,
                        "output_data": out,
                        "agent_type": t.agent_type,
                    })

                await engine.dispose()
        except Exception as exc:
            logger.debug("few_shot.retrieve(%s) DB query failed: %s", agent_type, exc)

        return examples

    except Exception as exc:
        logger.debug("few_shot.retrieve(%s) failed: %s", agent_type, exc)
        return []
