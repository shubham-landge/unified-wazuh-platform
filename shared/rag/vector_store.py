import json
import logging
from datetime import datetime, timezone
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from shared.rag.embeddings import embed_text, cosine_similarity

logger = logging.getLogger(__name__)


async def search_knowledge(query: str, db: AsyncSession, top_k: int = 5) -> list[dict]:
    query_emb = await embed_text(query)
    if not query_emb:
        return []

    try:
        from shared.models.knowledge_base import KnowledgeChunk
        result = await db.execute(
            select(KnowledgeChunk).order_by(KnowledgeChunk.created_at.desc()).limit(100)
        )
        chunks = result.scalars().all()
    except Exception:
        return []

    scored = []
    for chunk in chunks:
        emb = chunk.embedding
        if emb and isinstance(emb, (list, str)):
            if isinstance(emb, str):
                try:
                    emb = json.loads(emb)
                except Exception:
                    continue
            sim = cosine_similarity(query_emb, emb)
            scored.append((sim, chunk))

    scored.sort(key=lambda x: -x[0])
    return [
        {
            "id": str(c.id),
            "source": c.source,
            "chunk_text": c.chunk_text[:500],
            "similarity": round(s, 4),
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for s, c in scored[:top_k]
    ]


async def ingest_knowledge(source: str, text: str, db: AsyncSession, metadata: dict | None = None, commit: bool = True) -> bool:
    from shared.models.knowledge_base import KnowledgeChunk
    try:
        emb = await embed_text(text)
        chunk = KnowledgeChunk(
            source=source,
            chunk_text=text,
            embedding=emb,
            extra_meta=metadata or {},
            token_count=len(text.split()),
        )
        db.add(chunk)
        if commit:
            await db.commit()
        else:
            await db.flush()
        return True
    except Exception as e:
        logger.error("Failed to ingest knowledge: %s", e)
        return False


async def chunk_and_ingest(source: str, full_text: str, db: AsyncSession, chunk_size: int = 1000, overlap: int = 100, metadata: dict | None = None):
    words = full_text.split()
    chunks = []
    start = 0
    while start < len(words):
        end = start + chunk_size
        chunk = " ".join(words[start:end])
        chunks.append(chunk)
        start = end - overlap

    for i, chunk_text in enumerate(chunks):
        m = dict(metadata or {})
        m["chunk_index"] = i
        m["total_chunks"] = len(chunks)
        await ingest_knowledge(source, chunk_text, db, m)
