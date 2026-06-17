"""Tests for the cloud escalation tier in the TieredRouter.

Local fast/full tiers stay the default; escalation only triggers when enabled
AND either an incident is forced (cross-domain) or the routing score clears the
higher escalation threshold.
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from shared.connectors.llm_router import TieredRouter


def _high_score_alert():
    alert = MagicMock()
    alert.rule_level = 14
    alert.rule_id = 999
    alert.source_ip = "10.0.0.9"
    alert.agent_id = "agent-x"
    alert.mitre_technique = "T1569.002"
    alert.rule_firedtimes = 1
    alert.created_at = datetime.now(timezone.utc)
    return alert


@pytest.mark.asyncio
async def test_escalation_disabled_stays_local():
    router = TieredRouter()
    with patch("shared.config.settings.llm_tier_strategy", "auto"), \
         patch("shared.config.settings.llm_tier_escalation_enabled", False):
        provider = await router.get_provider(alert=_high_score_alert())
    # Never the cloud tier when escalation is off.
    assert "gemini" not in provider.name()


@pytest.mark.asyncio
async def test_force_escalation_routes_to_gemini():
    router = TieredRouter()
    with patch("shared.config.settings.llm_tier_escalation_enabled", True), \
         patch("shared.config.settings.llm_tier_escalation_provider", "gemini"), \
         patch("shared.config.settings.llm_tier_escalation_model", "gemini-2.5-flash"):
        provider = await router.get_provider(alert=None, force_escalation=True)
    assert "gemini" in provider.name()


@pytest.mark.asyncio
async def test_high_score_escalates_when_enabled():
    router = TieredRouter()
    with patch("shared.config.settings.llm_tier_strategy", "auto"), \
         patch("shared.config.settings.llm_tier_level_threshold", 10), \
         patch("shared.config.settings.llm_tier_escalation_enabled", True), \
         patch("shared.config.settings.llm_tier_escalation_score_threshold", 4), \
         patch("shared.config.settings.llm_tier_escalation_provider", "gemini"):
        provider = await router.get_provider(alert=_high_score_alert())
    assert "gemini" in provider.name()
