import uuid
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from shared.models.knowledge_base import KnowledgeChunk
from shared.rag.vector_store import search_knowledge, ingest_knowledge, chunk_and_ingest
from shared.rag.embeddings import embed_text

router = APIRouter(prefix="/rag", tags=["rag"])


class RAGQuery(BaseModel):
    query: str
    top_k: int = 5


class IngestRequest(BaseModel):
    source: str
    text: str
    metadata: dict | None = None


@router.post("/query")
async def query_knowledge(
    body: RAGQuery,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    results = await search_knowledge(body.query, db, top_k=body.top_k)
    return {
        "status": "success",
        "query": body.query,
        "count": len(results),
        "results": results,
    }


@router.get("/knowledge")
async def list_knowledge(
    source: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(KnowledgeChunk).order_by(KnowledgeChunk.created_at.desc()).limit(limit)
    if tenant_id:
        import uuid
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(KnowledgeChunk.tenant_id == tenant_uuid)
    
    if source:
        query = query.where(KnowledgeChunk.source == source)
    result = await db.execute(query)
    chunks = result.scalars().all()
    return {
        "status": "success",
        "count": len(chunks),
        "chunks": [
            {
                "id": str(c.id),
                "source": c.source,
                "chunk_text": c.chunk_text[:200],
                "token_count": c.token_count,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in chunks
        ],
    }


@router.post("/ingest")
async def ingest_knowledge_endpoint(
    body: IngestRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    success = await ingest_knowledge(body.source, body.text, db, body.metadata)
    if not success:
        raise HTTPException(status_code=500, detail="Ingestion failed")
    return {"status": "success", "source": body.source}


@router.delete("/knowledge/{chunk_id}")
async def delete_knowledge(
    chunk_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(chunk_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Invalid chunk ID")
    
    query = select(KnowledgeChunk).where(KnowledgeChunk.id == uid)
    if tenant_id:
        import uuid
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(KnowledgeChunk.tenant_id == tenant_uuid)
    
    chunk = (await db.execute(query)).scalar_one_or_none()
    if not chunk:
        raise HTTPException(status_code=404, detail="Knowledge chunk not found")
    await db.delete(chunk)
    await db.commit()
    return {"status": "success", "deleted": chunk_id}
