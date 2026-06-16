"""Tests for the noise-reduction pre-triage gate."""
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from shared import noise_reduction
from shared.noise_reduction import KEEP, DROP, DOWNGRADE


def _alert(level=8, rule_id=1001, groups=None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        rule_level=level,
        rule_id=rule_id,
        rule_groups=groups or [],
        agent_id="001",
        source_ip="10.0.0.5",
        tenant_id=None,
        rule_description="test",
    )


def _incident(count=1):
    return SimpleNamespace(id=uuid.uuid4(), alert_count=count)


@pytest.mark.asyncio
async def test_below_min_level_is_dropped():
    with patch.object(noise_reduction.settings, "noise_reduction_enabled", True), \
         patch.object(noise_reduction.settings, "triage_min_level", 7):
        decision = await noise_reduction.evaluate(AsyncMock(), _alert(level=4), None)
    assert decision.action == DROP
    assert not decision.should_triage
    assert "below_min_level" in decision.reason


@pytest.mark.asyncio
async def test_drop_rule_id():
    with patch.object(noise_reduction.settings, "noise_reduction_enabled", True), \
         patch.object(noise_reduction.settings, "triage_min_level", 7), \
         patch.object(noise_reduction.settings, "noise_drop_rule_ids", "1001,1002"):
        decision = await noise_reduction.evaluate(AsyncMock(), _alert(rule_id=1001), None)
    assert decision.action == DROP
    assert "drop_rule_id" in decision.reason


@pytest.mark.asyncio
async def test_drop_rule_group_substring():
    with patch.object(noise_reduction.settings, "noise_reduction_enabled", True), \
         patch.object(noise_reduction.settings, "triage_min_level", 7), \
         patch.object(noise_reduction.settings, "noise_drop_rule_groups", "firewall_allow"):
        alert = _alert(groups=["syslog", "fortigate_firewall_allow"])
        decision = await noise_reduction.evaluate(AsyncMock(), alert, None)
    assert decision.action == DROP
    assert "drop_rule_group" in decision.reason


@pytest.mark.asyncio
async def test_dedup_suppresses_after_threshold():
    with patch.object(noise_reduction.settings, "noise_reduction_enabled", True), \
         patch.object(noise_reduction.settings, "triage_min_level", 7), \
         patch.object(noise_reduction.settings, "alert_dedup_enabled", True), \
         patch.object(noise_reduction.settings, "noise_dedup_suppress_after", 3), \
         patch.object(noise_reduction.settings, "noise_drop_rule_ids", ""), \
         patch.object(noise_reduction.settings, "noise_drop_rule_groups", ""), \
         patch("shared.noise_reduction.dedup_alert_before_triage",
               new=AsyncMock(return_value=_incident(count=4))):
        decision = await noise_reduction.evaluate(AsyncMock(), _alert(), None)
    assert decision.action == DROP
    assert "dedup_suppressed" in decision.reason


@pytest.mark.asyncio
async def test_downgrade_pins_fast_tier():
    with patch.object(noise_reduction.settings, "noise_reduction_enabled", True), \
         patch.object(noise_reduction.settings, "triage_min_level", 7), \
         patch.object(noise_reduction.settings, "alert_dedup_enabled", True), \
         patch.object(noise_reduction.settings, "noise_dedup_suppress_after", 3), \
         patch.object(noise_reduction.settings, "noise_drop_rule_ids", ""), \
         patch.object(noise_reduction.settings, "noise_drop_rule_groups", ""), \
         patch.object(noise_reduction.settings, "noise_downgrade_rule_ids", "1001"), \
         patch("shared.noise_reduction.dedup_alert_before_triage",
               new=AsyncMock(return_value=_incident(count=1))):
        decision = await noise_reduction.evaluate(AsyncMock(), _alert(rule_id=1001), None)
    assert decision.action == DOWNGRADE
    assert decision.force_fast_tier is True
    assert decision.should_triage


@pytest.mark.asyncio
async def test_kept_when_nothing_matches():
    with patch.object(noise_reduction.settings, "noise_reduction_enabled", True), \
         patch.object(noise_reduction.settings, "triage_min_level", 7), \
         patch.object(noise_reduction.settings, "alert_dedup_enabled", True), \
         patch.object(noise_reduction.settings, "noise_dedup_suppress_after", 3), \
         patch.object(noise_reduction.settings, "noise_drop_rule_ids", ""), \
         patch.object(noise_reduction.settings, "noise_drop_rule_groups", ""), \
         patch.object(noise_reduction.settings, "noise_downgrade_rule_ids", ""), \
         patch("shared.noise_reduction.dedup_alert_before_triage",
               new=AsyncMock(return_value=_incident(count=1))):
        decision = await noise_reduction.evaluate(AsyncMock(), _alert(), None)
    assert decision.action == KEEP
    assert decision.should_triage
    assert decision.force_fast_tier is False


@pytest.mark.asyncio
async def test_disabled_keeps_everything():
    with patch.object(noise_reduction.settings, "noise_reduction_enabled", False):
        decision = await noise_reduction.evaluate(AsyncMock(), _alert(level=2), None)
    assert decision.action == KEEP


@pytest.mark.asyncio
async def test_force_fast_routes_to_fast_tier():
    """TieredRouter.get_provider(force_fast=True) must bypass scoring."""
    from shared.connectors.llm_router import TieredRouter
    router = TieredRouter()
    with patch.object(router, "_build_fast_provider", return_value="FAST") as fast, \
         patch.object(router, "_build_full_provider", return_value="FULL") as full:
        result = await router.get_provider(alert=_alert(level=15), force_fast=True)
    assert result == "FAST"
    fast.assert_called_once()
    full.assert_not_called()
