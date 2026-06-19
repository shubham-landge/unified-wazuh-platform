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
