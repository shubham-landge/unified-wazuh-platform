import asyncio
import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

import httpx
from pydantic import BaseModel, Field, field_validator, ValidationError

from shared.config import settings
from shared.connectors.circuit_breaker import CircuitBreaker

logger = logging.getLogger(__name__)

# Process-wide gate on concurrent local LLM inference. CPU-only Ollama can only
# run one generation at a time; letting requests pile up causes timeouts and
# parallel model loads (OOM). Lazily created so the limit binds per event loop.
_LLM_SEMAPHORE: asyncio.Semaphore | None = None


def _ollama_semaphore() -> asyncio.Semaphore:
    global _LLM_SEMAPHORE
    if _LLM_SEMAPHORE is None:
        limit = max(1, getattr(settings, "llm_max_concurrency", 1))
        _LLM_SEMAPHORE = asyncio.Semaphore(limit)
    return _LLM_SEMAPHORE

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
    return f"[BEGIN_UNTRUSTED_DATA]\n{text}\n[END_UNTRUSTED_DATA]"


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


class TriageOutput(BaseModel):
    """Structured, validated output from an LLM triage analysis."""

    verdict: str = Field(..., pattern=r"^(malicious|benign|suspicious)$")
    severity: str = Field(..., pattern=r"^(critical|high|medium|low)$")
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str = Field(..., max_length=500)
    mitre_techniques: list[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}

    @field_validator("mitre_techniques", mode="before")
    @classmethod
    def _normalize_mitre(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, list):
            return [str(item) for item in v]
        if isinstance(v, str):
            return [v]
        return [str(v)]

    @field_validator("summary")
    @classmethod
    def _strip_summary(cls, v: str) -> str:
        return v.strip()


def validate_and_parse(raw_response: str) -> TriageOutput:
    """Extract JSON from a raw LLM response and validate as TriageOutput.

    Handles markdown-wrapped JSON (```json ... ``` or ``` ... ```) and bare JSON.
    Raises ValidationError with details when extraction or validation fails.
    """
    candidate = raw_response.strip()
    errors: list[str] = []

    # ── Attempt 1: direct JSON parse ──
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return TriageOutput(**parsed)
        errors.append("direct parse did not yield a JSON object")
    except json.JSONDecodeError:
        errors.append("direct parse failed: invalid JSON")
    except ValidationError as exc:
        # Re-raise immediately — the JSON was structurally valid but schema-wrong
        raise

    # ── Attempt 2: extract from markdown code fence ──
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)```", candidate, re.DOTALL)
    if fence_match:
        inner = fence_match.group(1).strip()
        try:
            parsed = json.loads(inner)
            if isinstance(parsed, dict):
                return TriageOutput(**parsed)
            errors.append("markdown fence did not yield a JSON object")
        except json.JSONDecodeError:
            errors.append("markdown fence contained invalid JSON")
        except ValidationError as exc:
            raise

    # ── Attempt 3: find first { ... } block ──
    depth = 0
    start = None
    for i, ch in enumerate(candidate):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    parsed = json.loads(candidate[start : i + 1])
                    if isinstance(parsed, dict):
                        return TriageOutput(**parsed)
                except json.JSONDecodeError:
                    pass
                except ValidationError as exc:
                    raise
                start = None

    # ── All attempts exhausted ──
    raise ValidationError.from_exception_data(
        title="TriageOutput",
        line_errors=[
            {
                "type": "value_error",
                "loc": ("__root__",),
                "msg": f"Could not extract valid JSON from response. "
                       f"Attempts: {'; '.join(errors)}",
                "input": raw_response[:500],
                "ctx": {"error": f"JSON extraction failed: {'; '.join(errors)}"},
            }
        ],
    )


_CORRECTIVE_SUFFIX = (
    "\n\nYOUR PREVIOUS RESPONSE WAS INVALID. "
    "You MUST respond ONLY with a valid JSON object (no markdown, no commentary) "
    "containing exactly these fields:\n"
    '- "verdict": one of "malicious", "benign", "suspicious"\n'
    '- "severity": one of "critical", "high", "medium", "low"\n'
    '- "confidence": a float between 0.0 and 1.0\n'
    '- "summary": a string (max 500 characters)\n'
    '- "mitre_techniques": a list of MITRE ATT&CK technique IDs (e.g. ["T1059.001"])\n'
    "Respond with ONLY the JSON object. No intro, no outro, no markdown fences."
)


async def analyze_with_validation(
    provider: "LLMProvider",
    system_prompt: str,
    user_prompt: str,
    max_retries: int = 2,
) -> TriageOutput:
    """Call the LLM provider, validate structured output, and retry on failure.

    On each validation failure the corrective suffix is appended to *user_prompt*
    and the provider is called again. After *max_retries* attempts, a best-effort
    parse of the last response is attempted. If even that fails the last
    ValidationError is re-raised.
    """
    last_error: ValidationError | None = None
    last_result: dict | None = None
    current_prompt = user_prompt

    for attempt in range(max_retries + 1):
        result = await provider.analyze(system_prompt, current_prompt)
        last_result = result

        # Extract raw content — providers stuff parsed JSON into the result dict.
        # If the LLM returned good JSON, the keys are mixed in with metadata.
        # If parse_llm_response fell back, the raw text is in "raw_response".
        raw_content = result.get("raw_response") or result.get("summary") or ""
        if not raw_content and isinstance(result, dict):
            # Re-serialize the dict as a last resort (drops provider metadata keys
            # because TriageOutput.model_config ignores extras).
            raw_content = json.dumps(result)

        try:
            return validate_and_parse(raw_content)
        except ValidationError as exc:
            last_error = exc
            logger.warning(
                "LLM output validation failed (attempt %d/%d): %s",
                attempt + 1,
                max_retries + 1,
                exc,
            )
            if attempt < max_retries:
                current_prompt = user_prompt + _CORRECTIVE_SUFFIX

    # ── Max retries exhausted — best-effort parse ──
    if last_result is not None:
        try:
            best_effort = dict(last_result)
            # Drop metadata keys that confuse pydantic
            for key in ("success", "model", "tokens_input", "tokens_output", "cost", "raw_response"):
                best_effort.pop(key, None)
            return TriageOutput(**best_effort)
        except ValidationError:
            pass

    # Re-raise the last validation error
    if last_error is not None:
        raise last_error
    raise ValidationError.from_exception_data(
        title="TriageOutput",
        line_errors=[
            {
                "type": "value_error",
                "loc": ("__root__",),
                "msg": "analyze_with_validation failed: no response received from provider",
                "input": None,
                "ctx": {"error": "no response received from provider"},
            }
        ],
    )


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

    def _load_prompt_template(self, suffix: str = "triage") -> str:
        """Load a per-model prompt template from the prompts directory.

        Checks prompts/{model}_{suffix}.md, replacing any / with _ in the
        model name (e.g. notmythos:8b -> notmythos_8b).
        """
        from pathlib import Path
        safe_name = self.model.replace("/", "_").replace(":", "_")
        prompt_path = Path(settings.prompts_path) / f"{safe_name}_{suffix}.md"
        try:
            if prompt_path.is_file():
                return prompt_path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.debug("Failed to load prompt template %s: %s", prompt_path, exc)
        return ""

    async def analyze(self, system_prompt: str, user_prompt: str, **kwargs) -> dict:
        # Load per-model prompt template if available
        template = self._load_prompt_template("triage")
        if template:
            system_prompt = f"{template}\n\n{system_prompt}"

        # Sanitise attacker-controlled fields before the LLM sees them.
        # Only user_prompt is untrusted (alert data); system_prompt is trusted (SOC-controlled).
        user_prompt = sanitize_llm_input(user_prompt)
        masked_user = mask_sensitive_data(user_prompt) if settings.mask_sensitive_data else user_prompt

        # Apply config-driven model parameters with kwargs override
        temp = kwargs.get("temperature", settings.llm_model_temperature if hasattr(settings, "llm_model_temperature") else 0.35)
        top_p = kwargs.get("top_p", settings.llm_model_top_p if hasattr(settings, "llm_model_top_p") else 0.9)
        top_k = kwargs.get("top_k", settings.llm_model_top_k if hasattr(settings, "llm_model_top_k") else 40)
        repeat_penalty = kwargs.get("repeat_penalty", settings.llm_model_repeat_penalty if hasattr(settings, "llm_model_repeat_penalty") else 1.15)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": masked_user},
            ],
            "stream": False,
            # Constrain decoding to valid JSON so triage responses parse reliably
            # on the CPU-only models, which otherwise wrap JSON in prose.
            "format": "json",
            # Keep the model resident between requests — eliminates the cold-load
            # latency spike that dominates variance on CPU-only deploys.
            "keep_alive": getattr(settings, "ollama_keep_alive", "30m"),
            "options": {
                "temperature": temp,
                "top_p": top_p,
                "top_k": top_k,
                "repeat_penalty": repeat_penalty,
                # Bound output + context so a runaway generation can't double
                # latency or exceed the CPU context ceiling.
                "num_predict": getattr(settings, "llm_num_predict", 1024),
                "num_ctx": getattr(settings, "llm_num_ctx", 8192),
            },
        }

        async def _call():
            async with httpx.AsyncClient(timeout=300.0) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                return resp.json()

        # Serialize CPU-bound inference: concurrent calls just thrash one CPU and
        # time out. The semaphore queues them so each runs cleanly in turn.
        max_retries = getattr(settings, "llm_max_retries", 1)
        last_error = None
        async with _ollama_semaphore():
            for attempt in range(max_retries + 1):
                try:
                    data = await self._cb.call(_call)
                    content = data.get("message", {}).get("content", "")
                    result = parse_llm_response(content)
                    result["model"] = self.model
                    result["tokens_input"] = data.get("prompt_eval_count", 0)
                    result["tokens_output"] = data.get("eval_count", 0)
                    return result
                except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
                    last_error = e
                    if attempt < max_retries:
                        logger.warning("Ollama transient error (attempt %d/%d) for %s: %s",
                                       attempt + 1, max_retries + 1, self.model, e)
                        continue
                    logger.warning("Ollama request failed after retries for model %s: %s", self.model, e)
                    return {"success": False, "error": f"Ollama unavailable: {e}"}
                except Exception as e:
                    # Non-transient (circuit open, bad response): don't retry.
                    logger.error("Ollama request failed: %s", e)
                    return {"success": False, "error": str(e)}
        return {"success": False, "error": f"Ollama unavailable: {last_error}"}

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


def build_provider(provider_name: str, model: str | None = None) -> LLMProvider:
    """Construct a provider by name + optional model override.

    Used by the tiered router to materialise the fast / full / escalation tiers,
    which may each point at a different provider (e.g. local Ollama for fast/full,
    cloud Gemini for escalation).
    """
    name = (provider_name or "ollama").lower()
    if name == "ollama":
        return OllamaProvider(model=model)
    elif name == "openai":
        from shared.connectors.llm_openai import OpenAIProvider
        return OpenAIProvider(model=model) if model else OpenAIProvider()
    elif name == "gemini":
        from shared.connectors.llm_gemini import GeminiProvider
        return GeminiProvider(model=model)
    elif name == "claude":
        from shared.connectors.llm_claude import ClaudeProvider
        return ClaudeProvider(model=model) if model else ClaudeProvider()
    logger.warning("Unknown provider %s for tier; using Ollama", provider_name)
    return OllamaProvider(model=model)
