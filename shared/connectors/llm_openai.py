import logging
from time import perf_counter

import httpx

from shared.config import settings
from shared.connectors.llm_provider import (
    LLMProvider,
    mask_sensitive_data,
    normalize_llm_result,
    sanitize_llm_input,
)

logger = logging.getLogger(__name__)

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
MODEL_COSTS = {
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
}


class OpenaiProvider(LLMProvider):
    def __init__(self, model: str | None = None):
        self.model = model or settings.openai_model

    def _api_key(self) -> str:
        return (
            settings.openai_api_key.get_secret_value()
            if settings.openai_api_key
            else ""
        )

    async def analyze(self, system_prompt: str, user_prompt: str, **kwargs) -> dict:
        started = perf_counter()
        masked_user = (
            mask_sensitive_data(user_prompt)
            if settings.mask_sensitive_data
            else user_prompt
        )
        # Sanitize untrusted alert data before sending to cloud LLM
        masked_user = sanitize_llm_input(masked_user)
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": masked_user},
            ],
            "temperature": kwargs.get("temperature", 0.1),
        }
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    OPENAI_URL,
                    headers={"Authorization": f"Bearer {self._api_key()}"},
                    json=payload,
                )
                response.raise_for_status()
            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            usage = data.get("usage", {})
            return self._success(
                content,
                usage.get("prompt_tokens", 0),
                usage.get("completion_tokens", 0),
                started,
            )
        except httpx.TimeoutException:
            return self._failure("Request timed out", started)
        except Exception as exc:
            logger.error("OpenAI request failed: %s", exc)
            return self._failure(str(exc), started)

    async def health(self) -> dict:
        started = perf_counter()
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {self._api_key()}"},
                )
                response.raise_for_status()
            return {
                "success": True,
                "connected": True,
                "model": self.model,
                "latency_ms": round((perf_counter() - started) * 1000),
            }
        except Exception as exc:
            return {
                "success": False,
                "connected": False,
                "error": str(exc),
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
        return f"openai/{self.model}"


OpenAIProvider = OpenaiProvider
