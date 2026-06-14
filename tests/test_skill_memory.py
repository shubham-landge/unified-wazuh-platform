import uuid
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from shared.rag import skill_memory
from shared.models.agent import AgentTask


@pytest.mark.asyncio
async def test_add_experience_ingests_knowledge_chunk():
    task = AgentTask(
        run_id=uuid.uuid4(),
        agent_type="triage",
        input_data={"alert_id": "abc"},
        output_data={"verdict": "malicious"},
        status="completed",
    )
    task.id = uuid.uuid4()
    task.created_at = datetime.now(timezone.utc)

    mock_session = AsyncMock()

    with patch("shared.rag.skill_memory.settings") as mock_settings:
        mock_settings.rag_enabled = True
        with patch("shared.rag.skill_memory.ingest_knowledge", new=AsyncMock(return_value=True)) as mock_ingest:
            result = await skill_memory.add_experience(mock_session, task)

    assert result is True
    mock_ingest.assert_awaited_once()
    call_kwargs = mock_ingest.call_args.kwargs
    assert call_kwargs.get("commit") is False


@pytest.mark.asyncio
async def test_retrieve_similar_returns_skill_memories_only():
    mock_session = AsyncMock()

    with patch("shared.rag.skill_memory.settings") as mock_settings:
        mock_settings.rag_enabled = True
        with patch("shared.rag.skill_memory.search_knowledge", new=AsyncMock(return_value=[
            {"source": "skill_memory:triage:123", "chunk_text": "past triage", "similarity": 0.9},
            {"source": "knowledge_base:soc_playbook", "chunk_text": "playbook text", "similarity": 0.8},
        ])):
            results = await skill_memory.retrieve_similar(mock_session, "malicious login", agent_type="triage", k=5)

    assert len(results) == 1
    assert results[0]["source"] == "skill_memory:triage:123"


@pytest.mark.asyncio
async def test_build_few_shot_prompt_appends_memories():
    mock_session = AsyncMock()

    with patch("shared.rag.skill_memory.settings") as mock_settings:
        mock_settings.rag_enabled = True
        with patch("shared.rag.skill_memory.search_knowledge", new=AsyncMock(return_value=[
            {"source": "skill_memory:triage:123", "chunk_text": "past triage result", "similarity": 0.9},
        ])):
            prompt = await skill_memory.build_few_shot_prompt(mock_session, "suspicious login", agent_type="triage")

    assert "Relevant past experiences" in prompt
    assert "past triage result" in prompt
