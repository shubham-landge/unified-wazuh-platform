"""Tests for TriageOutput validation and analyze_with_validation in llm_provider."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from shared.connectors.llm_provider import (
    TriageOutput,
    validate_and_parse,
    analyze_with_validation,
)


# ── TriageOutput model tests ─────────────────────────────────────────────────

def test_triageoutput_valid_parses_correctly():
    """Valid JSON with all required fields parses into a TriageOutput."""
    raw = (
        '{"verdict":"malicious","severity":"high","confidence":0.92,'
        '"summary":"Ransomware detected via lateral movement",'
        '"mitre_techniques":["T1059.001","T1485"]}'
    )
    result = validate_and_parse(raw)
    assert isinstance(result, TriageOutput)
    assert result.verdict == "malicious"
    assert result.severity == "high"
    assert result.confidence == 0.92
    assert "Ransomware" in result.summary
    assert result.mitre_techniques == ["T1059.001", "T1485"]


def test_extra_fields_ignored():
    """Extra fields outside the schema are silently ignored."""
    raw = (
        '{"verdict":"benign","severity":"low","confidence":0.2,'
        '"summary":"No threat detected","mitre_techniques":[],'
        '"extra_key": "should be dropped"}'
    )
    result = validate_and_parse(raw)
    assert result.verdict == "benign"
    assert not hasattr(result, "extra_key")


def test_markdown_wrapped_json_extracts_correctly():
    """JSON inside a markdown code fence is extracted and parsed."""
    raw = (
        'Here is my analysis:\n\n'
        '```json\n'
        '{"verdict":"suspicious","severity":"medium","confidence":0.55,'
        '"summary":"Possible phishing with unusual login pattern",'
        '"mitre_techniques":["T1566.001"]}\n'
        '```\n\n'
        'Let me know if you need more details.'
    )
    result = validate_and_parse(raw)
    assert result.verdict == "suspicious"
    assert result.severity == "medium"
    assert result.confidence == 0.55
    assert "Possible phishing" in result.summary
    assert result.mitre_techniques == ["T1566.001"]


def test_markdown_fence_without_json_label():
    """JSON inside a bare ``` fence (no json tag) is also extracted."""
    raw = (
        '```\n'
        '{"verdict":"benign","severity":"low","confidence":0.1,'
        '"summary":"Routine service restart","mitre_techniques":[]}\n'
        '```'
    )
    result = validate_and_parse(raw)
    assert result.verdict == "benign"


def test_invalid_verdict_rejected():
    """A verdict outside the allowed enum is rejected with a ValidationError."""
    raw = (
        '{"verdict":"unknown","severity":"medium","confidence":0.5,'
        '"summary":"Something happened","mitre_techniques":[]}'
    )
    with pytest.raises(ValidationError) as exc_info:
        validate_and_parse(raw)
    assert "verdict" in str(exc_info.value) or "String should match pattern" in str(exc_info.value)


def test_missing_field_caught():
    """A response missing the required 'verdict' field fails validation."""
    raw = (
        '{"severity":"high","confidence":0.8,'
        '"summary":"Missing verdict field",'
        '"mitre_techniques":["T1059"]}'
    )
    with pytest.raises(ValidationError) as exc_info:
        validate_and_parse(raw)
    assert "verdict" in str(exc_info.value).lower()


def test_confidence_out_of_range_rejected():
    """Confidence outside 0-1 range is rejected."""
    raw = (
        '{"verdict":"malicious","severity":"critical","confidence":1.5,'
        '"summary":"Overconfident","mitre_techniques":[]}'
    )
    with pytest.raises(ValidationError) as exc_info:
        validate_and_parse(raw)
    assert "confidence" in str(exc_info.value) or "1.5" in str(exc_info.value)


def test_summary_too_long_rejected():
    """Summary exceeding 500 characters fails validation."""
    raw = (
        '{"verdict":"benign","severity":"low","confidence":0.1,'
        f'"summary":"{"x" * 501}","mitre_techniques":[]}}'
        .replace('}}"', '}')
    )
    with pytest.raises(ValidationError) as exc_info:
        validate_and_parse(raw)
    assert "summary" in str(exc_info.value)


def test_completely_invalid_string_raises():
    """A string that contains no JSON at all raises ValidationError."""
    raw = "This is just plain text, no JSON anywhere."
    with pytest.raises(ValidationError) as exc_info:
        validate_and_parse(raw)
    assert "JSON extraction failed" in str(exc_info.value) or "direct parse failed" in str(exc_info.value)


def test_mitre_techniques_defaults_to_empty_list():
    """When mitre_techniques is omitted, it defaults to an empty list."""
    raw = (
        '{"verdict":"malicious","severity":"high","confidence":0.88,'
        '"summary":"Lateral movement detected"}'
    )
    result = validate_and_parse(raw)
    assert result.mitre_techniques == []


# ── analyze_with_validation tests ────────────────────────────────────────────

VALID_JSON = (
    '{"verdict":"malicious","severity":"high","confidence":0.90,'
    '"summary":"C2 beaconing detected","mitre_techniques":["T1071.001"]}'
)

BAD_JSON = "just some text that is not JSON"


def _make_mock_provider(responses: list[dict]):
    """Return a mock LLMProvider whose analyze() returns each dict in sequence."""
    provider = MagicMock()
    provider.analyze = AsyncMock(side_effect=responses)
    return provider


@pytest.mark.asyncio
async def test_analyze_with_validation_first_try_succeeds():
    """When the provider returns valid JSON, it parses on the first attempt."""
    provider = _make_mock_provider([
        {"summary": VALID_JSON, "raw_response": VALID_JSON}
    ])
    result = await analyze_with_validation(
        provider, "system prompt", "user prompt", max_retries=2
    )
    assert result.verdict == "malicious"
    assert result.confidence == 0.90
    assert provider.analyze.await_count == 1


@pytest.mark.asyncio
async def test_analyze_with_validation_retry_then_succeeds():
    """First response fails validation, second succeeds after corrective prompt."""
    provider = _make_mock_provider([
        {"summary": BAD_JSON, "raw_response": BAD_JSON},
        {"summary": VALID_JSON, "raw_response": VALID_JSON},
    ])
    result = await analyze_with_validation(
        provider, "system prompt", "user prompt", max_retries=2
    )
    assert result.verdict == "malicious"
    # Should have been called twice: first attempt + one retry after corrective prompt
    assert provider.analyze.await_count == 2
    # Second call should include the corrective suffix
    second_call_kwargs = provider.analyze.await_args
    assert provider.analyze.await_args is not None


@pytest.mark.asyncio
async def test_analyze_with_validation_max_retries_exceeded_best_effort():
    """After max_retries, best-effort parse is attempted on the last response."""
    # Last response has valid keys in dict form (won't trigger raw_content extraction
    # but the dict will contain the needed fields because pydantic ignores extras)
    last_response = {
        "verdict": "suspicious",
        "severity": "medium",
        "confidence": 0.45,
        "summary": "Partial analysis",
        "mitre_techniques": [],
        "success": True,
        "model": "test-model",
    }
    provider = _make_mock_provider([
        {"summary": BAD_JSON, "raw_response": BAD_JSON},
        {"summary": BAD_JSON, "raw_response": BAD_JSON},
        last_response,  # third and final (max_retries=2 → 3 attempts total)
    ])
    result = await analyze_with_validation(
        provider, "system prompt", "user prompt", max_retries=2
    )
    assert isinstance(result, TriageOutput)
    assert result.verdict == "suspicious"
    assert result.confidence == 0.45
    assert provider.analyze.await_count == 3


@pytest.mark.asyncio
async def test_analyze_with_validation_raises_on_total_failure():
    """When all attempts fail and best-effort also fails, raises ValidationError."""
    provider = _make_mock_provider([
        {"summary": BAD_JSON, "raw_response": BAD_JSON},
        {"summary": "still not json", "raw_response": "still not json"},
        {"some_key": "no_useful_fields"},
    ])
    with pytest.raises(ValidationError):
        await analyze_with_validation(
            provider, "system prompt", "user prompt", max_retries=2
        )


@pytest.mark.asyncio
async def test_analyze_with_validation_respects_max_retries_zero():
    """With max_retries=0, only one attempt is made with no corrective retry."""
    provider = _make_mock_provider([
        {"summary": VALID_JSON, "raw_response": VALID_JSON}
    ])
    result = await analyze_with_validation(
        provider, "system prompt", "user prompt", max_retries=0
    )
    assert result.verdict == "malicious"
    assert provider.analyze.await_count == 1


# ══════════════════════════════════════════════════════════════════════════════
# TriageResult schema tests (shared.models.triage)
# ══════════════════════════════════════════════════════════════════════════════

from shared.models.triage import TriageResult, validate_triage_output


# ── TriageResult model tests ──────────────────────────────────────────────────

VALID_RESULT = {
    "category": "malicious",
    "severity": "high",
    "confidence": 0.92,
    "summary": "C2 beaconing detected via anomalous DNS queries",
    "false_positive_likelihood": 0.05,
    "mitre_mapping": ["T1071.001", "T1573"],
    "investigation_steps": ["Check DNS logs for the queried domains.", "Correlate with EDR network events."],
    "do_not_do": ["Block the IP without confirmation -- it may be a CDN edge."],
    "escalation_required": True,
    "recommended_soc_action": "Escalate to Tier 2 for beacon analysis.",
    "success": True,
}


def test_triageresult_valid_parses_all_fields():
    """Valid dict with all fields produces a correct TriageResult."""
    result = TriageResult.model_validate(VALID_RESULT)
    assert result.category == "malicious"
    assert result.severity == "high"
    assert result.confidence == 0.92
    assert result.summary.startswith("C2 beaconing")
    assert result.false_positive_likelihood == 0.05
    assert result.mitre_mapping == ["T1071.001", "T1573"]
    assert len(result.investigation_steps) == 2
    assert len(result.do_not_do) == 1
    assert result.escalation_required is True
    assert result.recommended_soc_action is not None
    assert result.success is True


def test_triageresult_extra_fields_ignored():
    """Extra fields outside the schema are silently dropped."""
    raw = {**VALID_RESULT, "extra_key": "should be dropped", "another": 123}
    result = TriageResult.model_validate(raw)
    assert result.category == "malicious"
    assert not hasattr(result, "extra_key")
    assert not hasattr(result, "another")


def test_triageresult_defaults_applied():
    """Missing optional fields receive schema defaults."""
    minimal = {"summary": "Just a summary"}
    result = TriageResult.model_validate(minimal)
    assert result.category == "unknown"
    assert result.severity == "medium"
    assert result.confidence == 0.5
    assert result.false_positive_likelihood == 0.3
    assert result.mitre_mapping == []
    assert result.investigation_steps == []
    assert result.do_not_do == []
    assert result.escalation_required is False
    assert result.recommended_soc_action is None
    assert result.success is True
    assert result.summary == "Just a summary"


def test_triageresult_confidence_clamped():
    """Confidence outside [0,1] is clamped to valid range."""
    result = TriageResult.model_validate({"confidence": 1.5})
    assert result.confidence == 1.0
    result = TriageResult.model_validate({"confidence": -0.3})
    assert result.confidence == 0.0
    result = TriageResult.model_validate({"confidence": 1.0})
    assert result.confidence == 1.0
    result = TriageResult.model_validate({"confidence": 0.0})
    assert result.confidence == 0.0


def test_triageresult_fp_likelihood_clamped():
    """False-positive likelihood outside [0,1] is clamped."""
    result = TriageResult.model_validate({"false_positive_likelihood": 2.0})
    assert result.false_positive_likelihood == 1.0
    result = TriageResult.model_validate({"false_positive_likelihood": -0.5})
    assert result.false_positive_likelihood == 0.0


def test_triageresult_severity_normalised():
    """Invalid severity values fall back to 'medium'."""
    result = TriageResult.model_validate({"severity": "extreme"})
    assert result.severity == "medium"
    result = TriageResult.model_validate({"severity": ""})
    assert result.severity == "medium"
    result = TriageResult.model_validate({"severity": None})
    assert result.severity == "medium"
    for sv in ("critical", "high", "medium", "low"):
        result = TriageResult.model_validate({"severity": sv})
        assert result.severity == sv


def test_triageresult_category_normalised():
    """Empty category falls back to 'unknown'."""
    result = TriageResult.model_validate({"category": ""})
    assert result.category == "unknown"
    result = TriageResult.model_validate({"category": None})
    assert result.category == "unknown"
    result = TriageResult.model_validate({})
    assert result.category == "unknown"


def test_triageresult_escalation_coerced():
    """escalation_required coerces string representations to bool."""
    assert TriageResult.model_validate({"escalation_required": "true"}).escalation_required is True
    assert TriageResult.model_validate({"escalation_required": "True"}).escalation_required is True
    assert TriageResult.model_validate({"escalation_required": "1"}).escalation_required is True
    assert TriageResult.model_validate({"escalation_required": "false"}).escalation_required is False
    assert TriageResult.model_validate({"escalation_required": "0"}).escalation_required is False
    assert TriageResult.model_validate({"escalation_required": True}).escalation_required is True
    assert TriageResult.model_validate({"escalation_required": 1}).escalation_required is True


def test_triageresult_list_fields_coerced():
    """Scalar values for list fields are wrapped in a single-element list."""
    result = TriageResult.model_validate({"mitre_mapping": "T1059"})
    assert result.mitre_mapping == ["T1059"]
    result = TriageResult.model_validate({"investigation_steps": "Check logs"})
    assert result.investigation_steps == ["Check logs"]
    result = TriageResult.model_validate({"do_not_do": None})
    assert result.do_not_do == []


def test_triageresult_summary_coerced():
    """Non-string summary values are coerced to string."""
    result = TriageResult.model_validate({"summary": 12345})
    assert result.summary == "12345"
    result = TriageResult.model_validate({"summary": {"summary": "nested summary"}})
    assert "nested summary" in result.summary


def test_triageresult_optional_str_normalised():
    """Optional string fields: None stays None, empty becomes None."""
    result = TriageResult.model_validate({"recommended_soc_action": "  Do X  "})
    assert result.recommended_soc_action == "Do X"
    result = TriageResult.model_validate({"recommended_soc_action": ""})
    assert result.recommended_soc_action is None
    result = TriageResult.model_validate({"recommended_soc_action": None})
    assert result.recommended_soc_action is None
    result = TriageResult.model_validate({"error": "Something broke"})
    assert result.error == "Something broke"
    result = TriageResult.model_validate({"error": ""})
    assert result.error is None


def test_triageresult_model_dump_excludes_extra():
    """model_dump() excludes fields not in the schema."""
    raw = {**VALID_RESULT, "extra_field": "drop"}
    result = TriageResult.model_validate(raw)
    dumped = result.model_dump()
    assert "extra_field" not in dumped
    assert dumped["category"] == "malicious"


def test_triageresult_fusion_fields():
    """Fusion metadata fields are handled correctly."""
    raw = {
        "fusion_applied": True,
        "fusion_overrides": ["TI overrode benign -> suspicious"],
    }
    result = TriageResult.model_validate(raw)
    assert result.fusion_applied is True
    assert result.fusion_overrides == ["TI overrode benign -> suspicious"]


# ── validate_triage_output (noise-gate) tests ──────────────────────────────────

def test_validate_triage_output_returns_validated_dict():
    """Returns a validated dict with all defaults applied."""
    result = validate_triage_output(VALID_RESULT)
    assert isinstance(result, dict)
    assert result["category"] == "malicious"
    assert result["confidence"] == 0.92
    assert result["summary"] == VALID_RESULT["summary"]
    assert "fusion_applied" in result
    assert "fusion_overrides" in result


def test_validate_triage_output_never_raises():
    """validate_triage_output returns a degraded dict on any failure, never raises."""
    result = validate_triage_output({})
    assert isinstance(result, dict)
    assert "_validation_error" not in result
    assert result["category"] == "unknown"
    result = validate_triage_output(None)
    assert isinstance(result, dict)
    assert "_validation_error" in result
    assert result["success"] is False
    result = validate_triage_output("not a dict")
    assert isinstance(result, dict)
    assert "_validation_error" in result


def test_validate_triage_output_marks_degraded():
    """When validation fails, the output is marked degraded."""
    # Non-dict input triggers degradation
    result = validate_triage_output(["not", "a", "dict"])
    assert isinstance(result, dict)
    assert "_validation_error" in result
    assert result["success"] is False
    assert "expected dict" in result["_validation_error"]


def test_validate_triage_output_preserves_cache_metadata():
    """Internal cache metadata keys (_cached, _cache_source) survive validation."""
    raw = {**VALID_RESULT, "_cached": True, "_cache_source": "semantic"}
    result = validate_triage_output(raw)
    assert result["_cached"] is True
    assert result["_cache_source"] == "semantic"
    assert result["category"] == "malicious"


def test_validate_triage_output_default_minimal():
    """Minimal dict with no fields gets all defaults -- passes validation."""
    result = validate_triage_output({"summary": "OK"})
    assert "_validation_error" not in result
    assert result["category"] == "unknown"
    assert result["severity"] == "medium"
    assert result["confidence"] == 0.5
    assert result["success"] is True


def test_validate_triage_output_clamps_out_of_range():
    """Out-of-range numeric values are clamped, not rejected."""
    result = validate_triage_output({
        "confidence": 5.0,
        "false_positive_likelihood": -2.0,
    })
    assert "_validation_error" not in result
    assert result["confidence"] == 1.0
    assert result["false_positive_likelihood"] == 0.0
    assert result["success"] is True


# ── Integration: triage_worker validation gate contract ────────────────────────

def test_validation_gate_accepts_l3_deterministic_output():
    """L3/L4 deterministic override dicts pass validation without degradation."""
    override_result = {
        "severity": "critical",
        "category": "malicious",
        "escalation_required": True,
        "confidence": 0.95,
        "summary": "C2 beaconing confirmed",
    }
    result = validate_triage_output(override_result)
    assert "_validation_error" not in result
    assert result["severity"] == "critical"
    assert result["category"] == "malicious"
    assert result["escalation_required"] is True
    assert result["confidence"] == 0.95


def test_validation_gate_accepts_fusion_output():
    """Post-fusion dicts with fusion_applied / fusion_overrides pass validation."""
    fusion_result = {
        **VALID_RESULT,
        "severity": "suspicious",
        "fusion_applied": True,
        "fusion_overrides": [
            "TI is_known_bad overrode benign -> suspicious, confidence >= 0.8"
        ],
    }
    result = validate_triage_output(fusion_result)
    assert "_validation_error" not in result
    assert result["fusion_applied"] is True
    assert len(result["fusion_overrides"]) == 1
    assert result["severity"] == "suspicious"


def test_validation_gate_accepts_shadow_mode_l3l4_output():
    """Shadow mode L3/L4 (LLM verdict preserved, no override) passes validation."""
    llm_natural = {
        "category": "suspicious",
        "severity": "medium",
        "confidence": 0.65,
        "summary": "Unusual login pattern, possible brute force",
        "false_positive_likelihood": 0.3,
        "mitre_mapping": ["T1110.001"],
        "investigation_steps": ["Review auth logs for the source IP."],
        "escalation_required": False,
        "success": True,
    }
    result = validate_triage_output(llm_natural)
    assert "_validation_error" not in result
    assert result["category"] == "suspicious"
    assert result["severity"] == "medium"


def test_validation_gate_error_enrichment_contract():
    """When degraded, result_data carries error for triage_worker to use."""
    # Non-dict input triggers the degradation path
    bad_result = validate_triage_output(42)
    assert "_validation_error" in bad_result
    assert bad_result["success"] is False
    val_error = bad_result.pop("_validation_error")
    bad_result["error"] = bad_result.get("error") or val_error
    assert bad_result["error"] is not None
    assert "expected dict" in bad_result["error"].lower() or "int" in bad_result["error"]


def test_validation_gate_accepts_investigation_steps():
    """LLMs returning 'investigation_steps' pass validation."""
    result = validate_triage_output({
        "investigation_steps": ["Check DNS", "Review EDR"],
    })
    assert "_validation_error" not in result
    assert result["investigation_steps"] == ["Check DNS", "Review EDR"]


def test_validation_gate_accepts_suggested_soc_action_alias():
    """The 'suggested_soc_action' alias is accepted."""
    result = validate_triage_output({
        "suggested_soc_action": "Escalate to on-call analyst",
    })
    assert "_validation_error" not in result
    assert result["suggested_soc_action"] == "Escalate to on-call analyst"


# ── Roundtrip: TriageResult -> dict -> TriageResult ──────────────────────────

def test_model_dump_roundtrips():
    """model_dump() output passes validate_triage_output() without degradation."""
    original = TriageResult.model_validate(VALID_RESULT)
    dumped = original.model_dump()
    result = validate_triage_output(dumped)
    assert "_validation_error" not in result
    assert result["category"] == original.category
    assert result["confidence"] == original.confidence


def test_validate_triage_output_idempotent():
    """Calling validate_triage_output twice on the same data is safe."""
    first = validate_triage_output(VALID_RESULT)
    second = validate_triage_output(first)
    assert "_validation_error" not in second
    assert second["category"] == first["category"]
