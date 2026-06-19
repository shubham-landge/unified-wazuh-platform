"""Skill memory layer for agent self-learning.

Stores completed AgentTask experiences as retrievable RAG chunks so that future
triage/planning/review steps can be guided by similar past outcomes.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from shared.config import settings
from shared.models.agent import AgentTask
from shared.rag.vector_store import ingest_knowledge, search_knowledge

logger = logging.getLogger(__name__)

SKILL_MEMORY_SOURCE_PREFIX = "skill_memory"


def _serialize_task(task: AgentTask) -> str:
    """Convert an AgentTask into a concise textual memory."""
    return json.dumps(
        {
            "agent_type": task.agent_type,
            "input": task.input_data,
            "output": task.output_data,
            "status": task.status,
            "error": task.error,
            "created_at": task.created_at.isoformat() if task.created_at else None,
        },
        default=str,
        indent=None,
    )


async def add_experience(session: AsyncSession, task: AgentTask, tenant_id: str | None = None) -> bool:
    """Persist a completed AgentTask as a skill-memory chunk."""
    if not settings.rag_enabled:
        return False

    try:
        text = _serialize_task(task)
        source = f"{SKILL_MEMORY_SOURCE_PREFIX}:{task.agent_type}:{task.id}"
        # Resolve tenant_id: prefer explicit arg, then task attribute, then default
        _tid = tenant_id or str(getattr(task, "tenant_id", "") or "")
        metadata = {
            "agent_type": task.agent_type,
            "task_id": str(task.id),
            "run_id": str(task.run_id),
            "status": task.status,
            "memory_type": "agent_experience",
            "tenant_id": _tid,
        }
        return await ingest_knowledge(source, text, session, metadata, commit=False)
    except Exception as exc:
        logger.warning("Failed to store skill memory for task %s: %s", task.id, exc)
        return False


async def retrieve_similar(
    session: AsyncSession,
    query: str,
    agent_type: str | None = None,
    k: int = 5,
    tenant_id: str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve the top-K most similar past agent experiences.

    tenant_id: if provided, only return memories tagged with this tenant.
    This prevents cross-tenant RAG contamination.
    """
    if not settings.rag_enabled:
        return []

    try:
        results = await search_knowledge(query, session, top_k=k * 3)
        filtered = []
        for r in results:
            src = r.get("source", "")
            if not src.startswith(SKILL_MEMORY_SOURCE_PREFIX):
                continue
            if agent_type and not src.startswith(f"{SKILL_MEMORY_SOURCE_PREFIX}:{agent_type}:"):
                continue
            # Tenant isolation: skip if memory belongs to a different tenant
            meta = r.get("metadata") or {}
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            mem_tenant = meta.get("tenant_id", "")
            if tenant_id and mem_tenant and mem_tenant != tenant_id:
                continue
            filtered.append(r)
        return filtered[:k]
    except Exception as exc:
        logger.warning("Skill memory retrieval failed: %s", exc)
        return []


async def build_few_shot_prompt(
    session: AsyncSession,
    query: str,
    agent_type: str | None = None,
    k: int = 3,
    tenant_id: str | None = None,
) -> str:
    """Build a few-shot prompt appendix from similar past experiences."""
    memories = await retrieve_similar(
        session, query, agent_type=agent_type, k=k, tenant_id=tenant_id
    )
    if not memories:
        return ""

    lines = ["\n# Relevant past experiences\n"]
    for i, mem in enumerate(memories, 1):
        # Sanitize retrieved chunks before injection (prevent prompt injection)
        chunk = mem.get("chunk_text", "")[:800]
        chunk = chunk.replace("<", "&lt;").replace(">", "&gt;")
        lines.append(f"{i}. {chunk}")
    return "\n".join(lines)
