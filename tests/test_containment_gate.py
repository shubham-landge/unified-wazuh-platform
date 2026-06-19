"""Tests for the containment gate policy engine and execute_with_gate."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.enrichment.risk_score import EnrichmentContext
from shared.enrichment.containment_gate import (
    ContainmentAction,
    ContainmentDecision,
    AuditRecord,
    check_policy,
    execute_with_gate,
)


def _ctx(**overrides) -> EnrichmentContext:
    """Build an EnrichmentContext with safe defaults, overridden as needed."""
    defaults = {
        "ti_is_known_bad": False,
        "is_crown_jewel": False,
    }
    return EnrichmentContext(**{**defaults, **overrides})


# ── check_policy tests ──────────────────────────────────────────────────────


@patch("shared.enrichment.containment_gate.settings")
def test_shadow_mode_blocks_all(mock_settings):
    """In shadow mode, every action is DENIED regardless of score or context."""
    mock_settings.automation_mode = "shadow"
    ctx = _ctx()
    decision, reason = check_policy(ContainmentAction.ISOLATE_HOST, ctx, score=90)
    assert decision == ContainmentDecision.DENY
    assert "shadow" in reason.lower()


@patch("shared.enrichment.containment_gate.settings")
def test_low_score_requires_approval(mock_settings):
    """Score < 60 gates all destructive actions behind human approval."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx()
    decision, reason = check_policy(ContainmentAction.BLOCK_IP, ctx, score=35)
    assert decision == ContainmentDecision.REQUIRE_APPROVAL
    assert "60" in reason


@patch("shared.enrichment.containment_gate.settings")
def test_high_score_allows_isolate_host(mock_settings):
    """Score >= 60 auto-approves ISOLATE_HOST."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx()
    decision, reason = check_policy(ContainmentAction.ISOLATE_HOST, ctx, score=65)
    assert decision == ContainmentDecision.ALLOW


@patch("shared.enrichment.containment_gate.settings")
def test_high_score_allows_block_ip(mock_settings):
    """Score >= 60 auto-approves BLOCK_IP."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx()
    decision, reason = check_policy(ContainmentAction.BLOCK_IP, ctx, score=75)
    assert decision == ContainmentDecision.ALLOW


@patch("shared.enrichment.containment_gate.settings")
def test_crown_jewel_requires_approval_for_destructive(mock_settings):
    """Even with high score, crown-jewel assets require human approval for destructive actions."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx(is_crown_jewel=True)
    decision, reason = check_policy(ContainmentAction.ISOLATE_HOST, ctx, score=85)
    assert decision == ContainmentDecision.REQUIRE_APPROVAL
    assert "crown-jewel" in reason.lower()


@patch("shared.enrichment.containment_gate.settings")
def test_ti_known_bad_allows_immediate_block(mock_settings):
    """TI known-bad overrides low score and allows ISOLATE_HOST/BLOCK_IP immediately."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx(ti_is_known_bad=True)
    # Score 25 is very low, but TI known-bad should override
    decision, reason = check_policy(ContainmentAction.BLOCK_IP, ctx, score=25)
    assert decision == ContainmentDecision.ALLOW
    assert "known-bad" in reason.lower()


@patch("shared.enrichment.containment_gate.settings")
def test_ti_known_bad_isolate_host(mock_settings):
    """TI known-bad also auto-allows ISOLATE_HOST."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx(ti_is_known_bad=True)
    decision, reason = check_policy(ContainmentAction.ISOLATE_HOST, ctx, score=20)
    assert decision == ContainmentDecision.ALLOW


@patch("shared.enrichment.containment_gate.settings")
def test_non_destructive_always_allowed(mock_settings):
    """SNAPSHOT_EVIDENCE is always ALLOWed, even in shadow mode."""
    # Shadow mode blocks everything except SNAPSHOT_EVIDENCE
    mock_settings.automation_mode = "shadow"
    ctx = _ctx(is_crown_jewel=True)
    decision, reason = check_policy(ContainmentAction.SNAPSHOT_EVIDENCE, ctx, score=0)
    assert decision == ContainmentDecision.ALLOW
    assert "non-destructive" in reason.lower()


@patch("shared.enrichment.containment_gate.settings")
def test_score_80_allows_disable_user(mock_settings):
    """Score >= 80 auto-approves DISABLE_USER."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx()
    decision, reason = check_policy(ContainmentAction.DISABLE_USER, ctx, score=85)
    assert decision == ContainmentDecision.ALLOW


@patch("shared.enrichment.containment_gate.settings")
def test_score_80_allows_quarantine_file(mock_settings):
    """Score >= 80 auto-approves QUARANTINE_FILE."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx()
    decision, reason = check_policy(ContainmentAction.QUARANTINE_FILE, ctx, score=90)
    assert decision == ContainmentDecision.ALLOW


@patch("shared.enrichment.containment_gate.settings")
def test_mid_score_disable_user_falls_back_to_approval(mock_settings):
    """DISABLE_USER with score 70 (>=60 but <80) falls through to approval."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx()
    decision, reason = check_policy(ContainmentAction.DISABLE_USER, ctx, score=70)
    assert decision == ContainmentDecision.REQUIRE_APPROVAL


@patch("shared.enrichment.containment_gate.settings")
def test_ti_known_bad_does_not_override_disable_user(mock_settings):
    """TI known-bad only auto-allows ISOLATE_HOST and BLOCK_IP, not DISABLE_USER."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx(ti_is_known_bad=True)
    decision, reason = check_policy(ContainmentAction.DISABLE_USER, ctx, score=25)
    # Score < 60 → REQUIRE_APPROVAL (TI override only applies to network/host actions)
    assert decision == ContainmentDecision.REQUIRE_APPROVAL


# ── execute_with_gate tests ──────────────────────────────────────────────────


@pytest.mark.asyncio
@patch("shared.enrichment.containment_gate.settings")
async def test_execute_with_gate_audit_record_created(mock_settings):
    """execute_with_gate returns a full result dict with audit trail."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx()

    result = await execute_with_gate(
        ContainmentAction.ISOLATE_HOST,
        target="192.168.1.100",
        ctx=ctx,
        score=75,
        session=None,  # no DB session
    )

    assert result["action"] == "isolate_host"
    assert result["target"] == "192.168.1.100"
    assert result["decision"] == "allow"
    assert result["executed"] is True
    assert "audit" in result
    assert result["audit"]["action"] == "isolate_host"
    assert result["audit"]["score"] == 75
    assert "timestamp" in result["audit"]


@pytest.mark.asyncio
@patch("shared.enrichment.containment_gate.settings")
async def test_execute_with_gate_denied_not_executed(mock_settings):
    """When denied, executed is False in the result."""
    mock_settings.automation_mode = "shadow"
    ctx = _ctx()

    result = await execute_with_gate(
        ContainmentAction.BLOCK_IP,
        target="10.0.0.5",
        ctx=ctx,
        score=90,
    )

    assert result["decision"] == "deny"
    assert result["executed"] is False


@pytest.mark.asyncio
@patch("shared.enrichment.containment_gate.settings")
async def test_execute_with_gate_approval_not_executed(mock_settings):
    """When approval is required, executed is False."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx(is_crown_jewel=True)

    result = await execute_with_gate(
        ContainmentAction.ISOLATE_HOST,
        target="db-server-01",
        ctx=ctx,
        score=90,
    )

    assert result["decision"] == "require_approval"
    assert result["executed"] is False


@pytest.mark.asyncio
@patch("shared.enrichment.containment_gate.settings")
async def test_execute_with_gate_audit_persists_to_session(mock_settings):
    """When a session is provided, the audit record is persisted."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx()

    mock_session = AsyncMock()
    result = await execute_with_gate(
        ContainmentAction.SNAPSHOT_EVIDENCE,
        target="/var/log/auth.log",
        ctx=ctx,
        score=10,
        session=mock_session,
    )

    assert result["decision"] == "allow"
    # Session should have been called with an INSERT
    mock_session.execute.assert_called_once()
    call_args = mock_session.execute.call_args[0]
    # First positional arg should contain "INSERT INTO containment_audit_log"
    assert "containment_audit_log" in call_args[0].lower()


@pytest.mark.asyncio
@patch("shared.enrichment.containment_gate.settings")
async def test_execute_with_gate_session_failure_is_best_effort(mock_settings):
    """If audit persistence fails, the decision is still returned."""
    mock_settings.automation_mode = "enforce"
    ctx = _ctx()

    mock_session = AsyncMock()
    mock_session.execute.side_effect = RuntimeError("DB connection lost")

    # Should not raise — audit persistence is best-effort
    result = await execute_with_gate(
        ContainmentAction.BLOCK_IP,
        target="203.0.113.42",
        ctx=ctx,
        score=80,
        session=mock_session,
    )

    assert result["decision"] == "allow"
    assert result["executed"] is True
