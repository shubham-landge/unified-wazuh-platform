import logging
from time import perf_counter

import httpx

from shared.config import settings
from shared.connectors.llm_provider import (
    LLMProvider,
    mask_sensitive_data,
    normalize_llm_result,
)

logger = logging.getLogger(__name__)

CLAUDE_URL = "https://api.anthropic.com/v1/messages"
MODEL_COSTS = {
    "claude-opus-4-8": (15.00, 75.00),
    "claude-sonnet-4-8": (3.00, 15.00),
}


class ClaudeProvider(LLMProvider):
    def __init__(self, model: str | None = None):
        self.model = model or settings.claude_model

    def _api_key(self) -> str:
        return (
            settings.claude_api_key.get_secret_value()
            if settings.claude_api_key
            else ""
        )

    async def analyze(self, system_prompt: str, user_prompt: str, **kwargs) -> dict:
        started = perf_counter()
        masked_user = (
            mask_sensitive_data(user_prompt)
            if settings.mask_sensitive_data
            else user_prompt
        )
        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": masked_user}],
            "max_tokens": kwargs.get("max_tokens", 2048),
            "temperature": kwargs.get("temperature", 0.1),
        }
        headers = {
            "x-api-key": self._api_key(),
            "anthropic-version": "2023-06-01",
        }
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    CLAUDE_URL,
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
            data = response.json()
            content = "".join(
                block.get("text", "")
                for block in data.get("content", [])
                if block.get("type") == "text"
            )
            usage = data.get("usage", {})
            return self._success(
                content,
                usage.get("input_tokens", 0),
                usage.get("output_tokens", 0),
                started,
            )
        except httpx.TimeoutException:
            return self._failure("Request timed out", started)
        except Exception as exc:
            logger.error("Claude request failed: %s", exc)
            return self._failure(str(exc), started)

    async def health(self) -> dict:
        started = perf_counter()
        result = await self.analyze("Reply briefly.", "health check", max_tokens=1)
        return {
            "success": result["success"],
            "connected": result["success"],
            "model": self.model,
            "error": result.get("error"),
            "latency_ms": round((perf_counter() - started) * 1000),
        }

    def _success(self, content: str, tokens_input: int, tokens_output: int, started):
        result = normalize_llm_result(content)
        input_rate, output_rate = MODEL_COSTS.get(self.model, (0.0, 0.0))
        result.update(
            {
                "model": self.model,
                "tokens_input": tokens_input,
                "tokens_output": tokens_output,
                "cost": round(
                    tokens_input * input_rate / 1_000_000
                    + tokens_output * output_rate / 1_000_000,
                    8,
                ),
                "latency_ms": round((perf_counter() - started) * 1000),
            }
        )
        return result

    def _failure(self, error: str, started) -> dict:
        return {
            "success": False,
            "error": error,
            "model": self.model,
            "tokens_input": 0,
            "tokens_output": 0,
            "cost": 0.0,
            "latency_ms": round((perf_counter() - started) * 1000),
        }

    def name(self) -> str:
        return f"claude/{self.model}"
