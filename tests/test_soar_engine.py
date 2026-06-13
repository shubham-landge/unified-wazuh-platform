"""Tests for SOAR playbook engine — trigger evaluation and action execution."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestTriggerEvaluation:
    def _eval(self, condition, alert):
        from shared.soar.engine import _evaluate_condition
        return _evaluate_condition(condition, alert)

    def test_simple_eq(self):
        assert self._eval({"field": "severity", "op": "eq", "value": "critical"}, {"severity": "critical"}) is True
        assert self._eval({"field": "severity", "op": "eq", "value": "critical"}, {"severity": "high"}) is False

    def test_gte(self):
        assert self._eval({"field": "rule_level", "op": "gte", "value": 12}, {"rule_level": 14}) is True
        assert self._eval({"field": "rule_level", "op": "gte", "value": 12}, {"rule_level": 10}) is False

    def test_contains(self):
        assert self._eval({"field": "rule_description", "op": "contains", "value": "brute"}, {"rule_description": "SSH brute force"}) is True

    def test_in_operator(self):
        assert self._eval({"field": "severity", "op": "in", "value": ["critical", "high"]}, {"severity": "high"}) is True
        assert self._eval({"field": "severity", "op": "in", "value": ["critical", "high"]}, {"severity": "low"}) is False

    def test_and_condition(self):
        cond = {"and": [
            {"field": "rule_level", "op": "gte", "value": 10},
            {"field": "severity", "op": "eq", "value": "high"},
        ]}
        assert self._eval(cond, {"rule_level": 12, "severity": "high"}) is True
        assert self._eval(cond, {"rule_level": 8, "severity": "high"}) is False

    def test_or_condition(self):
        cond = {"or": [
            {"field": "rule_level", "op": "gte", "value": 14},
            {"field": "severity", "op": "eq", "value": "critical"},
        ]}
        assert self._eval(cond, {"rule_level": 7, "severity": "critical"}) is True
        assert self._eval(cond, {"rule_level": 7, "severity": "low"}) is False

    def test_not_condition(self):
        cond = {"not": {"field": "severity", "op": "eq", "value": "low"}}
        assert self._eval(cond, {"severity": "high"}) is True
        assert self._eval(cond, {"severity": "low"}) is False

    def test_missing_field(self):
        assert self._eval({"field": "nonexistent", "op": "eq", "value": "val"}, {}) is False

    def test_exists_operator(self):
        assert self._eval({"field": "source_ip", "op": "exists", "value": None}, {"source_ip": "1.2.3.4"}) is True
        assert self._eval({"field": "source_ip", "op": "exists", "value": None}, {"source_ip": None}) is False

    def test_unknown_operator(self):
        result = self._eval({"field": "x", "op": "zap", "value": "y"}, {"x": "y"})
        assert result is False


class TestSOARActions:
    async def test_log_action(self):
        from shared.soar.actions import execute_action, ActionContext
        ctx = ActionContext(alert={"id": "abc"}, session=None, redis_client=None)
        result = await execute_action({"type": "log", "message": "test"}, ctx)
        assert result["success"] is True

    async def test_wait_action(self):
        from shared.soar.actions import execute_action, ActionContext
        ctx = ActionContext(alert={}, session=None, redis_client=None)
        result = await execute_action({"type": "wait", "seconds": 0}, ctx)
        assert result["success"] is True
        assert result["waited_seconds"] == 0

    async def test_wait_capped_at_300s(self):
        from shared.soar.actions import execute_action, ActionContext
        import asyncio
        ctx = ActionContext(alert={}, session=None, redis_client=None)
        # 999s should be capped — test doesn't actually sleep since we mock asyncio.sleep
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = await execute_action({"type": "wait", "seconds": 999}, ctx)
            mock_sleep.assert_called_once_with(300)
        assert result["success"] is True

    async def test_set_severity_action(self):
        from shared.soar.actions import execute_action, ActionContext
        ctx = ActionContext(alert={"severity": "medium"}, session=None, redis_client=None)
        await execute_action({"type": "set_severity", "severity": "high"}, ctx)
        assert ctx.alert["severity"] == "high"

    async def test_notify_action_enqueues(self):
        from shared.soar.actions import execute_action, ActionContext
        mock_redis = AsyncMock()
        ctx = ActionContext(alert={"id": "test-alert-id"}, session=None, redis_client=mock_redis)
        result = await execute_action({"type": "notify", "channel": "slack", "payload": {}}, ctx)
        assert result["success"] is True
        mock_redis.lpush.assert_called_once()

    async def test_enrich_ti_action_enqueues(self):
        from shared.soar.actions import execute_action, ActionContext
        mock_redis = AsyncMock()
        ctx = ActionContext(alert={"id": "test-id"}, session=None, redis_client=mock_redis)
        result = await execute_action({"type": "enrich_threat_intel"}, ctx)
        assert result["success"] is True
        mock_redis.lpush.assert_called_once()

    async def test_webhook_action_no_url(self):
        from shared.soar.actions import execute_action, ActionContext
        ctx = ActionContext(alert={}, session=None, redis_client=None)
        result = await execute_action({"type": "webhook"}, ctx)
        assert result["success"] is False

    async def test_unknown_action_type(self):
        from shared.soar.actions import execute_action, ActionContext
        ctx = ActionContext(alert={}, session=None, redis_client=None)
        result = await execute_action({"type": "does_not_exist"}, ctx)
        assert result["success"] is False
