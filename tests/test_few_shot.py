import pytest
import uuid
from unittest.mock import AsyncMock, patch
from shared.rag import few_shot

@pytest.mark.asyncio
async def test_few_shot_retrieve():
    from unittest.mock import AsyncMock, MagicMock
    from shared.models.agent import AgentTask

    with patch("shared.rag.few_shot.s") as mock_settings:
        mock_settings.rag_skill_memory_enabled = True
        with patch("shared.rag.few_shot.create_async_engine") as mock_engine:
            mock_session = AsyncMock()
            mock_session.execute.return_value.scalars.return_value.all.return_value = []
            
            mock_session_factory = MagicMock()
            mock_session_factory.return_value.__aenter__.return_value = mock_session
            mock_session_factory.return_value.__aexit__ = AsyncMock()
            
            mock_eng = AsyncMock()
            mock_eng.dispose = AsyncMock()
            mock_engine.return_value = mock_eng
            
            with patch("shared.rag.few_shot.async_sessionmaker", return_value=mock_session_factory):
                results = await few_shot.retrieve("triage", {}, technique_ids=["T1003.001"])
                assert len(results) >= 1
                assert results[0]["type"] == "skill"
                assert results[0]["technique"] == "T1003.001"
