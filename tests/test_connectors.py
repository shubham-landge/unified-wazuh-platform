import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock


@pytest.mark.asyncio
async def test_ollama_provider_analyze():
    from shared.connectors.llm_provider import OllamaProvider

    provider = OllamaProvider(model="qwen2.5-coder:3b")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": {"content": '{"summary": "Test alert", "severity": "medium", "confidence": 0.8}'},
        "prompt_eval_count": 50,
        "eval_count": 30,
    }

    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
        result = await provider.analyze(
            system_prompt="You are a SOC assistant.",
            user_prompt="Analyze this: test",
        )

    assert result["success"] is True
    assert result["summary"] == "Test alert"
    assert result["severity"] == "medium"
    assert result["confidence"] == 0.8


@pytest.mark.asyncio
async def test_ollama_provider_health():
    from shared.connectors.llm_provider import OllamaProvider

    provider = OllamaProvider(model="qwen2.5-coder:3b")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "models": [{"name": "qwen2.5-coder:3b"}]
    }

    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
        health = await provider.health()

    assert health["connected"] is True
    assert "qwen2.5-coder:3b" in health["models"]


@pytest.mark.asyncio
async def test_mask_sensitive_data_ips():
    from shared.connectors.llm_provider import mask_sensitive_data

    text = "Source IP: 192.168.1.100 accessed from 10.0.0.50"
    masked = mask_sensitive_data(text)
    assert "[IP_REDACTED]" in masked
    assert "192.168.1.100" not in masked


@pytest.mark.asyncio
async def test_mask_sensitive_data_tokens():
    from shared.connectors.llm_provider import mask_sensitive_data

    text = "Token: ghp_abcdefghijklmnopqrstuvwxyz12345678901234"
    masked = mask_sensitive_data(text)
    assert "[TOKEN_REDACTED]" in masked


@pytest.mark.asyncio
async def test_mask_sensitive_data_emails():
    from shared.connectors.llm_provider import mask_sensitive_data

    text = "User: admin@company.com accessed system"
    masked = mask_sensitive_data(text)
    assert "[EMAIL_REDACTED]" in masked
    assert "admin@company.com" not in masked


@pytest.mark.asyncio
async def test_get_provider_default():
    from shared.connectors.llm_provider import get_provider

    provider = get_provider()
    assert provider is not None
    assert "ollama" in provider.name()


@pytest.mark.asyncio
async def test_ollama_provider_malformed_json():
    from shared.connectors.llm_provider import OllamaProvider

    provider = OllamaProvider(model="qwen2.5-coder:3b")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": {"content": "This is not JSON"},
        "prompt_eval_count": 10,
        "eval_count": 5,
    }

    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
        result = await provider.analyze(
            system_prompt="Test",
            user_prompt="Test",
        )

    assert result["success"] is True
    assert "raw_response" in result
    assert result["summary"] == "This is not JSON"
