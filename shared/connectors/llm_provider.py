import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

import httpx

from shared.config import settings

logger = logging.getLogger(__name__)

SENSITIVE_PATTERNS = [
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '[IP_REDACTED]'),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), '[EMAIL_REDACTED]'),
    (re.compile(r'(?i)(password|secret|token|api_key|apikey|auth|credential)\s*[:=]\s*\S+'), r'\1: [REDACTED]'),
    (re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b'), '[TOKEN_REDACTED]'),
    (re.compile(r'\b(?:sk-[A-Za-z0-9]{20,}|pk-[A-Za-z0-9]{20,})\b'), '[API_KEY_REDACTED]'),
    (re.compile(r'\b[A-Za-z0-9+/=]{40,}\b'), '[CREDENTIAL_REDACTED]'),
]


def mask_sensitive_data(text: str) -> str:
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class LLMProvider(ABC):
    @abstractmethod
    async def analyze(self, system_prompt: str, user_prompt: str, **kwargs) -> dict:
        pass

    @abstractmethod
    async def health(self) -> dict:
        pass

    @abstractmethod
    def name(self) -> str:
        pass


class OllamaProvider(LLMProvider):
    def __init__(self, model: str = None):
        self.base_url = settings.ollama_base_url.rstrip("/")
        self.model = model or settings.ollama_model

    async def analyze(self, system_prompt: str, user_prompt: str, **kwargs) -> dict:
        masked_user = mask_sensitive_data(user_prompt) if settings.mask_sensitive_data else user_prompt
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": masked_user},
            ],
            "stream": False,
            "options": {"temperature": kwargs.get("temperature", 0.1)},
        }

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()

            content = data.get("message", {}).get("content", "")
            result = self._parse_response(content)
            result["model"] = self.model
            result["tokens_input"] = data.get("prompt_eval_count", 0)
            result["tokens_output"] = data.get("eval_count", 0)
            return result
        except httpx.TimeoutException:
            logger.warning("Ollama request timed out for model %s", self.model)
            return {"success": False, "error": "Request timed out"}
        except Exception as e:
            logger.error("Ollama request failed: %s", e)
            return {"success": False, "error": str(e)}

    async def health(self) -> dict:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
                models = [m["name"] for m in data.get("models", [])]
                return {
                    "connected": True,
                    "models": models,
                    "model_loaded": self.model in models,
                }
        except Exception as e:
            return {"connected": False, "error": str(e)}

    def name(self) -> str:
        return f"ollama/{self.model}"

    def _parse_response(self, content: str) -> dict:
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        return {"success": True, "summary": content, "raw_response": content}


def get_provider() -> LLMProvider:
    provider_name = settings.llm_provider.lower()
    if provider_name == "ollama":
        return OllamaProvider()
    elif provider_name == "openai":
            from shared.connectors.llm_openai import OpenAIProvider
        return OpenAIProvider()
    elif provider_name == "gemini":
            from shared.connectors.llm_gemini import GeminiProvider
        return GeminiProvider()
    elif provider_name == "claude":
            from shared.connectors.llm_claude import ClaudeProvider
        return ClaudeProvider()
    else:
        logger.warning("Unknown LLM provider %s, falling back to Ollama", provider_name)
        return OllamaProvider()
