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


