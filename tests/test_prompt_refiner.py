import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from services.worker.app.prompt_refiner import PromptRefiner
from shared.models.feedback import UserFeedback
from shared.models.ai_triage_result import AiTriageResult

@pytest.mark.asyncio
async def test_prompt_refiner_refine_loop():
    refiner = PromptRefiner()
    refiner.session_factory = MagicMock()
    mock_session = AsyncMock()
    refiner.session_factory.return_value.__aenter__.return_value = mock_session

    fb = UserFeedback(rating=1, correction_text="wrong category")
    fb.triage_result_id = "triage-id"
    triage = AiTriageResult(prompt_text="original", response_text="result")

    mock_res_fb = MagicMock()
    mock_res_fb.scalars.return_value.all.return_value = [fb]

    mock_res_triage = MagicMock()
    mock_res_triage.scalar_one_or_none.return_value = triage

    mock_session.execute = AsyncMock()
    mock_session.execute.side_effect = [
        mock_res_fb,
        mock_res_triage
    ]

    mock_provider = AsyncMock()
    mock_provider.analyze.return_value = {"summary": "refined prompt template"}

    with patch("services.worker.app.prompt_refiner.get_provider", return_value=mock_provider):
        with patch("builtins.open", MagicMock()) as mock_open:
            await refiner.refine_loop()
            mock_provider.analyze.assert_awaited_once()
            mock_open.assert_called_once_with("prompts/best_skill.md", "w")
