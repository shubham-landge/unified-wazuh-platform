import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import json


class TestRAGIntegration:
    @pytest.mark.asyncio
    async def test_embed_text_success(self):
        from shared.rag.embeddings import embed_text

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"embedding": [0.1, 0.2, 0.3]}

        with patch("httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(return_value=mock_resp)
            client_cls.return_value = client

            result = await embed_text("test text")

        assert result == [0.1, 0.2, 0.3]

    @pytest.mark.asyncio
    async def test_embed_text_failure_returns_none(self):
        from shared.rag.embeddings import embed_text

        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient") as client_cls:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(return_value=mock_resp)
            client_cls.return_value = client

            result = await embed_text("test text")

        assert result is None

    def test_cosine_similarity_zero_vectors(self):
        from shared.rag.embeddings import cosine_similarity

        assert cosine_similarity([0.0, 0.0], [1.0, 0.0]) == 0.0

    def test_cosine_similarity_partial(self):
        from shared.rag.embeddings import cosine_similarity

        a = [1.0, 2.0, 3.0]
        b = [4.0, 5.0, 6.0]
        sim = cosine_similarity(a, b)
        assert 0.9 < sim < 1.0

    @pytest.mark.asyncio
    async def test_chunk_and_ingest_creates_chunks(self):
        from shared.rag.vector_store import chunk_and_ingest

        mock_db = AsyncMock()
        text = "word " * 2500  # ~2500 words, should create 3 chunks at chunk_size=1000, overlap=100

        with patch("shared.rag.vector_store.ingest_knowledge", new_callable=AsyncMock) as mock_ingest:
            await chunk_and_ingest("test.md", text, mock_db, chunk_size=1000, overlap=100)

        assert mock_ingest.await_count >= 2

    @pytest.mark.asyncio
    async def test_search_knowledge_empty_db(self):
        from shared.rag.vector_store import search_knowledge

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        with patch("shared.rag.embeddings.embed_text", new_callable=AsyncMock, return_value=[0.1, 0.2]):
            results = await search_knowledge("test query", mock_db, top_k=5)

        assert results == []


class TestKnowledgeBaseAPI:
    def test_knowledge_chunk_model_fields(self):
        from shared.models.knowledge_base import KnowledgeChunk
        assert hasattr(KnowledgeChunk, "extra_meta")
        assert hasattr(KnowledgeChunk, "embedding")
        assert hasattr(KnowledgeChunk, "chunk_text")

    @pytest.mark.asyncio
    async def test_ingest_knowledge_success(self):
        from shared.rag.vector_store import ingest_knowledge

        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        with patch("shared.rag.embeddings.embed_text", new_callable=AsyncMock, return_value=[0.5, 0.5]):
            result = await ingest_knowledge("test.md", "test content", mock_db)

        assert result is True

    @pytest.mark.asyncio
    async def test_ingest_knowledge_with_tenant_id(self):
        from shared.rag.vector_store import ingest_knowledge

        mock_db = AsyncMock()
        mock_db.add = MagicMock()

        with patch("shared.rag.vector_store.embed_text", new_callable=AsyncMock, return_value=[0.5, 0.5]):
            result = await ingest_knowledge(
                "test.md", "test content", mock_db,
                metadata={"tenant_id": "tenant-abc"},
                tenant_id="tenant-abc",
            )

        assert result is True
        added_chunk = mock_db.add.call_args[0][0]
        assert added_chunk.tenant_id == "tenant-abc"
        assert added_chunk.extra_meta.get("tenant_id") == "tenant-abc"

    @pytest.mark.asyncio
    async def test_search_knowledge_returns_metadata(self):
        from shared.rag.vector_store import search_knowledge

        mock_db = AsyncMock()
        mock_chunk = MagicMock()
        mock_chunk.id = uuid.uuid4()
        mock_chunk.source = "skill_memory:triage:abc"
        mock_chunk.chunk_text = "past triage result"
        mock_chunk.extra_meta = {"tenant_id": "tenant-abc", "agent_type": "triage", "memory_type": "triage_verdict"}
        mock_chunk.embedding = [0.1, 0.2]
        mock_chunk.created_at = None

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_chunk]
        mock_db.execute = AsyncMock(return_value=mock_result)

        # Patch embed_text where it's used (vector_store module-level reference)
        with patch("shared.rag.vector_store.embed_text", new_callable=AsyncMock, return_value=[0.1, 0.2]):
            results = await search_knowledge("test query", mock_db, top_k=5)

        assert len(results) == 1
        assert results[0]["metadata"] == {"tenant_id": "tenant-abc", "agent_type": "triage", "memory_type": "triage_verdict"}


class TestTriageRAGPersistence:
    @pytest.mark.asyncio
    async def test_persist_triage_verdict_includes_tenant_id(self):
        from shared.triage_rag import persist_triage_verdict
        from shared.models.alert import Alert

        alert = Alert(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            rule_id=1001,
            rule_description="Test rule",
            rule_level=7,
            mitre_tactic="TA0001",
            mitre_technique="T1566",
            source_ip="10.0.0.1",
            user_name="test_user",
        )
        verdict = {
            "triage_id": str(uuid.uuid4()),
            "summary": "Test summary",
            "category": "phishing",
            "severity": "high",
            "confidence": 0.85,
            "false_positive_likelihood": 0.1,
            "escalation_required": False,
        }
        mock_session = AsyncMock()

        async def fake_ingest(source, text, db, metadata=None, commit=True, tenant_id=None):
            mock_ingest.call_args = type("Args", (), {"kwargs": {"metadata": metadata, "tenant_id": tenant_id}})()
            mock_ingest.call_args.kwargs = {"metadata": metadata, "tenant_id": tenant_id}
            return True

        with patch("shared.triage_rag.settings") as mock_settings:
            mock_settings.rag_enabled = True
            mock_settings.rag_skill_memory_enabled = True
            with patch("shared.rag.vector_store.ingest_knowledge", new=fake_ingest) as mock_ingest:
                result = await persist_triage_verdict(mock_session, alert, verdict)

        assert result is True
        call_kwargs = mock_ingest.call_args.kwargs
        metadata = call_kwargs.get("metadata", {})
        assert metadata.get("tenant_id") == str(alert.tenant_id)
        assert metadata.get("agent_type") == "triage"
        assert metadata.get("memory_type") == "triage_verdict"
        assert call_kwargs.get("tenant_id") == str(alert.tenant_id)


