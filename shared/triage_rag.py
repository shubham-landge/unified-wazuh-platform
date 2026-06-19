"""RAG augmentation for the triage prompt.

Retrieves similar past triage verdicts from skill memory and builds a few-shot
appendix for the LLM system prompt.
"""

import json
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from shared.config import settings
from shared.models.alert import Alert
from shared.rag import skill_memory

logger = logging.getLogger(__name__)


async def build_triage_context(
    session: AsyncSession,
    alert: Alert,
    k: int = 3,
    tenant_id: str | None = None,
) -> str:
    """Return a system-prompt appendix with relevant past triage verdicts."""
    if not settings.rag_enabled or not settings.rag_skill_memory_enabled:
        return ""

    query_parts = [
        str(alert.rule_description or ""),
        str(alert.mitre_technique or ""),
        str(alert.mitre_tactic or ""),
        str(alert.source_ip or ""),
        str(alert.user_name or ""),
    ]
    query = " | ".join(p for p in query_parts if p).strip()
    if not query:
        return ""

    try:
        memories = await skill_memory.retrieve_similar(
            session,
            query,
            agent_type="triage",
            k=k,
            tenant_id=tenant_id,
        )
    except Exception as exc:
        logger.debug("Triage RAG retrieval failed: %s", exc)
        return ""

    if not memories:
        return ""

    lines = ["\n# Similar past triage verdicts (use as guidance only)", ""]
    for i, mem in enumerate(memories, 1):
        text = mem.get("chunk_text", "")
        # Truncate long memories.
        if len(text) > 800:
            text = text[:800] + "..."
        lines.append(f"{i}. {text}")

    return "\n".join(lines)


async def persist_triage_verdict(
    session: AsyncSession,
    alert: Alert,
    verdict: dict,
) -> bool:
    """Store a triage verdict as a skill-memory chunk for future retrieval."""
    if not settings.rag_enabled or not settings.rag_skill_memory_enabled:
        return False

    text = json.dumps(
        {
            "rule_description": alert.rule_description,
            "rule_id": alert.rule_id,
            "rule_level": alert.rule_level,
            "mitre": f"{alert.mitre_tactic} / {alert.mitre_technique}",
            "source_ip": alert.source_ip,
            "user_name": alert.user_name,
            "summary": verdict.get("summary"),
            "category": verdict.get("category"),
            "severity": verdict.get("severity"),
            "confidence": verdict.get("confidence"),
            "false_positive_likelihood": verdict.get("false_positive_likelihood"),
            "escalation_required": verdict.get("escalation_required"),
        },
        default=str,
        indent=None,
    )

    try:
        from shared.rag.vector_store import ingest_knowledge
        source = f"skill_memory:triage:{alert.id}:{verdict.get('triage_id','unknown')}"
        _tid = str(alert.tenant_id) if alert.tenant_id else None
        metadata = {
            "agent_type": "triage",
            "alert_id": str(alert.id),
            "rule_id": alert.rule_id,
            "memory_type": "triage_verdict",
            "tenant_id": _tid,
        }
        return await ingest_knowledge(source, text, session, metadata, commit=False, tenant_id=_tid)
    except Exception as exc:
        logger.warning("Failed to persist triage verdict to skill memory: %s", exc)
        return False
