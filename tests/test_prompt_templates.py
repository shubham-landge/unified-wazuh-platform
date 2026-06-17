import pytest
import os
import yaml
from shared.rag import few_shot

def test_load_notmythos_prompt_returns_content():
    path = os.path.join("prompts", "notmythos_triage.md")
    assert os.path.exists(path)
    with open(path, "r") as f:
        content = f.read()
    assert content.strip() != ""

def test_skill_frontmatter_parses():
    path = os.path.join("prompts", "skills", "T1003.001.md")
    assert os.path.exists(path)
    with open(path, "r") as f:
        content = f.read()
    parts = content.split("---")
    assert len(parts) >= 3
    fm = yaml.safe_load(parts[1])
    assert fm["skill_id"] == "T1003.001"
    assert fm["tactic"] == "Credential Access"
    assert fm["technique"] == "T1003.001"

@pytest.mark.asyncio
async def test_load_skill_returns_content():
    content = await few_shot.load_skill("T1003.001")
    assert content.strip() != ""
    assert "Detection Logic" in content

@pytest.mark.asyncio
async def test_load_skill_returns_empty_for_missing():
    content = await few_shot.load_skill("T9999.999")
    assert content == ""

@pytest.mark.asyncio
async def test_few_shot_includes_skills():
    from unittest.mock import patch, AsyncMock, MagicMock
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
                import sys
                import traceback
                # We patch retrieve to print its exception or we catch it here.
                # Actually, retrieve catches the exception and returns []. If retrieve returned None, it must be because of something else.
                # Oh, retrieve returns examples which is a list. If it returned None, maybe retrieve did not return anything or crashed without returning?
                # No, retrieve has:
                # except Exception as exc:
                #     logger.debug("few_shot.retrieve(%s) failed: %s", agent_type, exc)
                #     return []
                # If retrieve returned None, wait, it has return examples. Where could it return None?
                # Let's inspect retrieve signature again.
                # Oh! retrieve returned None because "except Exception" returned [] but maybe it actually returned None? No, it returns [] in except block.
                # Wait, "assert res is not None, 'retrieve returned None!'" failed because res is None? No, AssertionError: retrieve returned None! assert None is not None.
                # Yes, res is indeed None. Let's see if retrieve actually returns None somewhere.
                # No, look at retrieve:
                # it returns examples. Let's trace it carefully.
                res = await few_shot.retrieve("triage", {}, technique_ids=["T1003.001"])
                if res is None:
                    # let's run it directly without mocking to see if we get an exception or if it is None.
                    pass
                assert res is not None
                assert len(res) >= 1
                assert res[0]["type"] == "skill"
                assert res[0]["technique"] == "T1003.001"

def test_prompt_template_has_required_sections():
    path = os.path.join("prompts", "notmythos_triage.md")
    with open(path, "r") as f:
        content = f.read()
    assert "SYSTEM" in content
    assert "PARAMETER temperature" in content
    assert "mitre_mapping" in content
