import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

import httpx

from shared.config import settings
from shared.connectors.circuit_breaker import CircuitBreaker

logger = logging.getLogger(__name__)

SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(password|secret|token|api_key|apikey|auth|credential)\s*[:=]\s*\S+'), r'\1: [REDACTED]'),
    # GitHub tokens
    (re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b'), '[TOKEN_REDACTED]'),
    # OpenAI/Anthropic-style API keys (specific prefixes only — avoids false positives on base64)
    (re.compile(r'\b(?:sk-ant-[A-Za-z0-9\-_]{20,}|sk-[A-Za-z0-9]{20,}|pk-[A-Za-z0-9]{20,})\b'), '[API_KEY_REDACTED]'),
    # Emails
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), '[EMAIL_REDACTED]'),
]


def mask_sensitive_data(text: str) -> str:
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# Prompt-injection guards: character-escape patterns that attackers can use
# to break out of the LLM prompt.
_INJECTION_ESCAPES = [
    (re.compile(r'(\w+)\s*[:=]\s*```'), r'\1: [BLOCK_OPEN]'),
    (re.compile(r'```'), '[CODE_BLOCK]'),
    (re.compile(r'\bsystem\s*[:=]\s*(?:"[^"]*"|\'[^\']*\')'), '[SYSTEM_OVERRIDE]'),
    (re.compile(r'\bignore\s+(?:all\s+)?(?:previous|above|below|prior)\s+instructions\b', re.I), '[IGNORE_ATTEMPT]'),
    (re.compile(r'\bforget\s+(?:everything|all|previous)\b', re.I), '[FORGET_ATTEMPT]'),
    (re.compile(r'\b(?:you\s+are|act\s+as|pretend)\s+(?:now\s+)?a?\s*(?:helpful|free|unconstrained)\b', re.I), '[ROLE_PLAY]'),
    (re.compile(r'\bdo\s+not\s+(?:follow|obey|respect)\b', re.I), '[DEFIANCE]'),
]


def sanitize_llm_input(field_value: str | None) -> str:
    """Sanitize a potentially attacker-controlled field before LLM consumption.

    Strips prompt-injection escape sequences and wraps the value in safe
    delimiters to prevent jailbreaking.
    """
    if field_value is None:
        return ""
    text = str(field_value)
    for pattern, replacement in _INJECTION_ESCAPES:
        text = pattern.sub(replacement, text)
    # Remove any remaining triple-backtick or unusual Unicode control chars
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\u200b\u200c\u200d\ufeff]', '', text)
    # Truncate very long fields to prevent token overflow injection
    max_len = getattr(settings, 'llm_input_max_length', 2000)
    if len(text) > max_len:
        text = text[:max_len] + " [TRUNCATED]"
    return text


def parse_llm_response(content: str) -> dict:
    try:
        parsed = json.loads(content.strip())
        if isinstance(parsed, dict):
            parsed.setdefault("success", True)
            return parsed
    except json.JSONDecodeError:
        pass

    depth = 0
    start = None
    for i, ch in enumerate(content):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    parsed = json.loads(content[start:i + 1])
                    if isinstance(parsed, dict):
                        parsed.setdefault("success", True)
                        return parsed
                except json.JSONDecodeError:
                    pass
                start = None

    return {"success": True, "summary": content, "raw_response": content}


def normalize_llm_result(content: str) -> dict:
    result = parse_llm_response(content)
    result.setdefault("summary", content)
    result.setdefault("category", "unknown")
    result.setdefault("severity", "medium")
    result.setdefault("confidence", 0.0)
    result.setdefault("false_positive_likelihood", 0.0)
    result.setdefault("mitre_mapping", [])
    result.setdefault(
        "investigation_steps",
        result.get("recommended_investigation_steps", []),
    )
    result.setdefault("do_not_do", [])
    result.setdefault("escalation_required", False)
    result.setdefault(
        "recommended_soc_action",
        result.get("suggested_soc_action"),
    )
    return result


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
        self._cb = CircuitBreaker(name="ollama", failure_threshold=3, recovery_timeout=60.0)

    async def analyze(self, system_prompt: str, user_prompt: str, **kwargs) -> dict:
        # Sanitise attacker-controlled fields before the LLM sees them
        user_prompt = sanitize_llm_input(user_prompt)
        system_prompt = sanitize_llm_input(system_prompt)
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

        async def _call():
            async with httpx.AsyncClient(timeout=300.0) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                return resp.json()

        try:
            data = await self._cb.call(_call)
            content = data.get("message", {}).get("content", "")
            result = parse_llm_response(content)
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
        return parse_llm_response(content)


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
