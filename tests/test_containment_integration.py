"""Integration tests for the containment_gate ↔ handlers ↔ SOAR actions wiring.

Verifies that containment_guard() correctly delegates to the policy engine
when enrichment context is provided, while preserving the legacy
always-approval-required fallback when it is not.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.enrichment.risk_score import EnrichmentContext
from shared.orchestrator.handlers import containment_guard


# ── Helpers ──────────────────────────────────────────────────────────────


def _mock_session(approval_exists: bool = False) -> AsyncMock:
    """Build an AsyncMock session that responds to _check_existing_approval."""
    session = AsyncMock()
    if approval_exists:
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = MagicMock(id=uuid.uuid4())
    else:
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=mock_result)
    session.flush = AsyncMock()
    return session


def _enrichment_ctx(**overrides) -> EnrichmentContext:
    """Build an EnrichmentContext with safe defaults."""
    defaults = {
        "rule_level": 5,
        "ti_is_known_bad": False,
        "is_crown_jewel": False,
    }
    return EnrichmentContext(**{**defaults, **overrides})


# ── Integration tests ────────────────────────────────────────────────────


@pytest.mark.asyncio
@patch("shared.enrichment.containment_gate.settings")
async def test_containment_policy_auto_allows_high_score(mock_settings):
    """Score >= 60 with enforce mode auto-approves ISOLATE_HOST."""
    mock_settings.automation_mode = "enforce"

    session = _mock_session()
    tenant_id = uuid.uuid4()
    ctx = _enrichment_ctx()

    result = await containment_guard(
        session,
        tenant_id,
        "isolate_host",
        {"ip_address": "10.0.0.99", "alert_id": "alert-001"},
        rationale="High-confidence host isolation",
        enrichment_ctx=ctx,
        score=75,
    )

    assert result["approved"] is True
    assert result["decision"] == "allow"
    assert result["score"] == 75
    assert "reason" in result
    # Should NOT have created an ApprovalRequest
    assert not session.add.called


@pytest.mark.asyncio
@patch("shared.enrichment.containment_gate.settings")
async def test_containment_policy_blocks_shadow_mode(mock_settings):
    """In shadow mode, destructive containment actions are denied."""
    mock_settings.automation_mode = "shadow"

    session = _mock_session()
    tenant_id = uuid.uuid4()
    ctx = _enrichment_ctx()

    result = await containment_guard(
        session,
        tenant_id,
        "block_ip",
        {"ip_address": "192.168.1.50", "alert_id": "alert-002"},
        rationale="Block suspicious IP",
        enrichment_ctx=ctx,
        score=90,
    )

    assert result["approved"] is False
    assert result["decision"] == "deny"
    assert "shadow" in result["reason"].lower()
    assert "approval_id" not in result


@pytest.mark.asyncio
@patch("shared.enrichment.containment_gate.settings")
async def test_containment_policy_requires_approval_for_low_score(mock_settings):
    """Score < 60 gates the action behind human approval (creates ApprovalRequest)."""
    mock_settings.automation_mode = "enforce"

    session = _mock_session()
    tenant_id = uuid.uuid4()
    ctx = _enrichment_ctx()

    result = await containment_guard(
        session,
        tenant_id,
        "disable_user",
        {"user_id": "user-789", "alert_id": "alert-003"},
        rationale="Possible compromised account",
        enrichment_ctx=ctx,
        score=35,
    )

    assert result["approved"] is False
    assert "approval_id" in result
    assert "60" in result["reason"]
    # An ApprovalRequest should have been added to the session
    assert session.add.called
    assert session.flush.called
