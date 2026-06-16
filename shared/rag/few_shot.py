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


async def retrieve(agent_type: str, input_data: dict, top_k: int = 5) -> list[dict]:
    """Return top-K similar past tasks from skill memory as few-shot examples.

    Each returned dict has at least ``input_data`` and ``output_data`` keys
    so the consumer can build a few-shot prompt.

    When skill memory is disabled or the query fails, an empty list is
    returned so consuming handlers degrade gracefully.
    """
    if not s.rag_skill_memory_enabled:
        return []

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

            examples = []
            for t in tasks:
                inp = t.input_data or {}
                out = t.output_data or {}
                examples.append({
                    "input_data": inp,
                    "output_data": out,
                    "agent_type": t.agent_type,
                })

            await engine.dispose()
            return examples

    except Exception as exc:
        logger.debug("few_shot.retrieve(%s) failed: %s", agent_type, exc)
        return []
