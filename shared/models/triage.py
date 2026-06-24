"""Output validation schema for LLM triage responses.

Provides TriageResult — a permissive Pydantic model that validates structural
correctness of LLM output without being overly strict.  Type coercion, range
clamping, and safe defaults keep the pipeline resilient to imperfect LLM
responses while catching truly broken output.

The ``validate_triage_output`` function implements the noise-gate pattern:
attempt validation, log on failure, return a degraded-but-usable dict so the
triage worker never drops an alert due to schema mismatch.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_SEVERITY_VALUES = frozenset({"critical", "high", "medium", "low", "suspicious"})


# ── TriageResult schema ───────────────────────────────────────────────────────

class TriageResult(BaseModel):
    """Validated LLM triage output.

    Permissive by design: coerces types, applies safe defaults, and clamps
    numeric ranges.  Extra fields are silently ignored.  The caller should
    always call :func:`validate_triage_output` rather than construct directly
    so the noise-gate fallback path is consistently applied.
    """

    category: str = Field(default="unknown", max_length=255)
    severity: str = Field(default="medium", max_length=16)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    summary: str = Field(default="", max_length=2000)
    false_positive_likelihood: float = Field(default=0.3, ge=0.0, le=1.0)
    mitre_mapping: list = Field(default_factory=list)
    investigation_steps: list = Field(default_factory=list)
    do_not_do: list = Field(default_factory=list)
    escalation_required: bool = False
    recommended_soc_action: str | None = Field(default=None, max_length=1000)
    suggested_soc_action: str | None = Field(default=None, max_length=1000)
    success: bool = True
    error: str | None = Field(default=None, max_length=2000)
    error_message: str | None = Field(default=None, max_length=2000)

    # Fusion metadata (set by decision_fusion.fuse_verdict)
    fusion_applied: bool = False
    fusion_overrides: list[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}

    # ── Validators ────────────────────────────────────────────────────────

    @field_validator("confidence", "false_positive_likelihood", mode="before")
    @classmethod
    def _coerce_float_range(cls, v: Any) -> float:
        """Coerce to float and clamp to [0, 1].  Uncoercible values → default."""
        if v is None:
            return 0.5
        try:
            f = float(v)
        except (TypeError, ValueError):
            return 0.5
        return max(0.0, min(1.0, f))

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, v: Any) -> str:
        """Normalise severity string; invalid / missing → 'medium'."""
        if v is None or str(v).strip() == "":
            return "medium"
        sv = str(v).strip().lower()
        if sv not in _SEVERITY_VALUES:
            return "medium"
        return sv

    @field_validator("category", mode="before")
    @classmethod
    def _normalize_category(cls, v: Any) -> str:
        """Normalise category string; empty → 'unknown'."""
        if v is None or str(v).strip() == "":
            return "unknown"
        return str(v).strip()[:255]

    @field_validator("escalation_required", mode="before")
    @classmethod
    def _coerce_bool(cls, v: Any) -> bool:
        """Coerce common truthy/falsy representations to bool."""
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() in ("true", "1", "yes")
        try:
            return bool(v)
        except Exception:
            return False

    @field_validator("mitre_mapping", "investigation_steps", "do_not_do",
                     mode="before")
    @classmethod
    def _coerce_list(cls, v: Any) -> list:
        """Coerce scalar → single-item list; None → empty list."""
        if v is None:
            return []
        if isinstance(v, list):
            return v
        if isinstance(v, (str, int, float, bool)):
            return [v]
        try:
            return list(v)
        except Exception:
            return []

    @field_validator("summary", mode="before")
    @classmethod
    def _coerce_summary(cls, v: Any) -> str:
        """Coerce summary to str; None / missing → empty."""
        if v is None:
            return ""
        if isinstance(v, dict):
            # LLM sometimes nests the summary inside another key
            return str(v.get("summary", v.get("description", str(v))))
        return str(v)[:2000]

    @field_validator("recommended_soc_action", "suggested_soc_action",
                     "error", "error_message", mode="before")
    @classmethod
    def _coerce_optional_str(cls, v: Any) -> str | None:
        """Coerce optional string fields."""
        if v is None:
            return None
        if isinstance(v, str):
            s = v.strip()
            return s if s else None
        return str(v).strip() or None


# ── Validation gate ───────────────────────────────────────────────────────────

def validate_triage_output(result_data: dict | None) -> dict:
    """Validate LLM response against the TriageResult schema (noise-gate pattern).

    On success the returned dict has all defaults applied and invalid fields
    stripped.  On failure a *degraded* dict is returned with ``_validation_error``
    set — the caller can proceed with best-effort data.

    This is a pure function: it never raises.
    """
    if not isinstance(result_data, dict):
        return _build_degraded_result(
            result_data,
            f"validate_triage_output: expected dict, got {type(result_data).__name__}",
        )
    try:
        validated = TriageResult.model_validate(result_data)
        out = validated.model_dump()
        # Preserve internal cache metadata keys the schema doesn't model
        for key in ("_cached", "_cache_source"):
            if key in result_data:
                out[key] = result_data[key]
        return out
    except Exception as exc:
        logger.warning("TriageResult validation failed: %s", exc)
        # Build a degraded-but-usable dict by merging the raw data with defaults
        degraded = _build_degraded_result(result_data, str(exc))
        return degraded


def _build_degraded_result(raw: dict | None, error_text: str) -> dict:
    """Merge raw LLM output with safe defaults, flagging the validation failure.

    The caller should treat ``_validation_error`` presence as a signal that
    the result is degraded (e.g. set ``success=False`` in the triage row).
    """
    # Start with schema defaults so every field is present
    safe = TriageResult().model_dump()
    # Overlay whatever the LLM actually returned (if anything)
    if isinstance(raw, dict):
        for key, value in raw.items():
            if key in safe:
                safe[key] = value
    # Flag the degradation
    safe["_validation_error"] = error_text
    safe["success"] = False
    # Preserve cache metadata
    if isinstance(raw, dict):
        for key in ("_cached", "_cache_source"):
            if key in raw:
                safe[key] = raw[key]
    return safe
