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

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
MODEL_COSTS = {
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 5.00),
}


class GeminiProvider(LLMProvider):
    def __init__(self, model: str | None = None):
        self.model = model or settings.gemini_model

    def _api_key(self) -> str:
        return (
            settings.gemini_api_key.get_secret_value()
            if settings.gemini_api_key
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
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": masked_user}]}],
            "generationConfig": {
                "temperature": kwargs.get("temperature", 0.1),
                "responseMimeType": "application/json",
            },
        }
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{GEMINI_BASE_URL}/{self.model}:generateContent",
                    params={"key": self._api_key()},
                    json=payload,
                )
                response.raise_for_status()
            data = response.json()
            parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
            content = "".join(part.get("text", "") for part in parts)
            usage = data.get("usageMetadata", {})
            return self._success(
                content,
                usage.get("promptTokenCount", 0),
                usage.get("candidatesTokenCount", 0),
                started,
            )
        except httpx.TimeoutException:
            return self._failure("Request timed out", started)
        except Exception as exc:
            logger.error("Gemini request failed: %s", exc)
            return self._failure(str(exc), started)

    async def health(self) -> dict:
        started = perf_counter()
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.get(
                    f"{GEMINI_BASE_URL}/{self.model}",
                    params={"key": self._api_key()},
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
        return f"gemini/{self.model}"
