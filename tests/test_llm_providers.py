from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.connectors.llm_claude import ClaudeProvider
from shared.connectors.llm_gemini import GeminiProvider
from shared.connectors.llm_openai import OpenaiProvider

TRIAGE_JSON = (
    '{"summary":"Investigate endpoint","category":"malware","severity":"high",'
    '"confidence":0.9,"false_positive_likelihood":0.1,"mitre_mapping":[],'
    '"recommended_investigation_steps":["isolate"],"do_not_do":[],'
    '"escalation_required":true,"recommended_soc_action":"Open a case"}'
)


def _response(data):
    response = MagicMock()
    response.json.return_value = data
    response.raise_for_status.return_value = None
    return response


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "response_data", "tokens_input", "tokens_output"),
    [
        (
            OpenaiProvider("gpt-4o-mini"),
            {
                "choices": [{"message": {"content": TRIAGE_JSON}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50},
            },
            100,
            50,
        ),
        (
            GeminiProvider("gemini-2.5-flash"),
            {
                "candidates": [{"content": {"parts": [{"text": TRIAGE_JSON}]}}],
                "usageMetadata": {
                    "promptTokenCount": 100,
                    "candidatesTokenCount": 50,
                },
            },
            100,
            50,
        ),
        (
            ClaudeProvider("claude-sonnet-4-8"),
            {
                "content": [{"type": "text", "text": TRIAGE_JSON}],
                "usage": {"input_tokens": 100, "output_tokens": 50},
            },
            100,
            50,
        ),
    ],
)
async def test_provider_analyze(provider, response_data, tokens_input, tokens_output):
    with patch("httpx.AsyncClient") as client_class:
        client = client_class.return_value.__aenter__.return_value
        client.post = AsyncMock(return_value=_response(response_data))
        result = await provider.analyze(
            "SOC system prompt",
            "source_ip=10.0.0.1 password=secret",
        )

    assert result["success"] is True
    assert result["summary"] == "Investigate endpoint"
    assert result["investigation_steps"] == ["isolate"]
    assert result["tokens_input"] == tokens_input
    assert result["tokens_output"] == tokens_output
    assert result["cost"] > 0
    sent_payload = client.post.await_args.kwargs["json"]
    assert "10.0.0.1" in str(sent_payload)
    assert "password=secret" not in str(sent_payload)
    assert "[REDACTED]" in str(sent_payload)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider",
    [
        OpenaiProvider("gpt-4o"),
        GeminiProvider("gemini-2.5-flash"),
        ClaudeProvider("claude-opus-4-8"),
    ],
)
async def test_provider_health(provider):
    with patch("httpx.AsyncClient") as client_class:
        client = client_class.return_value.__aenter__.return_value
        client.get = AsyncMock(return_value=_response({}))
        client.post = AsyncMock(
            return_value=_response(
                {
                    "content": [{"type": "text", "text": "{}"}],
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
            )
        )
        result = await provider.health()

    assert result["success"] is True
    assert result["connected"] is True


@pytest.mark.asyncio
async def test_provider_timeout_never_raises():
    with patch("httpx.AsyncClient") as client_class:
        client = client_class.return_value.__aenter__.return_value
        client.post = AsyncMock(side_effect=__import__("httpx").TimeoutException("slow"))
        result = await OpenaiProvider().analyze("system", "user")

    assert result["success"] is False
    assert result["error"] == "Request timed out"
