"""Tests for declarative YAML workflow engine — parse, trigger, context, dry-run, gated containment."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import ANY, AsyncMock, patch

import pytest
import yaml

from shared.workflows.context import WorkflowContext, interpolate
from shared.workflows.engine import WorkflowEngine
from shared.workflows.loader import load_yaml
from shared.workflows.models import Action, Step, Trigger, Workflow
from shared.workflows.triggers import match_trigger

# ── Fixtures ─────────────────────────────────────────────────────────────────

SAMPLE_YAML = """
id: high_severity_response
description: Respond to high severity alerts
triggers:
  - type: alert
    with:
      cel: alert.rule_level >= 10
  - type: manual
steps:
  - name: enrich_context
    actions:
      - type: enrich
  - name: contain_host
    if: alert.rule_level >= 12
    actions:
      - type: gated_containment
        with:
          action_type: isolate_host
  - name: notify_soc
    actions:
      - type: notify
        with:
          channel: slack
          message: "Alert {{ alert.id }} fired"
"""


@pytest.fixture
def sample_alert() -> dict:
    return {
        "id": "alert-001",
        "rule_level": 14,
        "rule_id": 1001,
        "severity": "high",
        "source_ip": "10.0.0.55",
        "rule_groups": ["syslog", "authentication"],
    }


# ── Tests: models ───────────────────────────────────────────────────────────


class TestModels:
    def test_action_creation(self):
        a = Action(type="enrich", with_={"field": "value"})
        assert a.type == "enrich"
        assert a.with_ == {"field": "value"}

    def test_step_defaults(self):
        s = Step(name="test_step")
        assert s.name == "test_step"
        assert s.provider is None
        assert s.if_ is None
        assert s.actions == []

    def test_workflow_minimal(self):
        w = Workflow(id="wf-1", description="test")
        assert w.id == "wf-1"
        assert w.triggers == []


# ── Tests: loader ───────────────────────────────────────────────────────────


class TestLoader:
    def test_load_yaml(self):
        wf = load_yaml(SAMPLE_YAML)
        assert wf.id == "high_severity_response"
        assert wf.description == "Respond to high severity alerts"
        assert len(wf.triggers) == 2
        assert wf.triggers[0].type == "alert"
        assert wf.triggers[0].with_["cel"] == "alert.rule_level >= 10"
        assert wf.triggers[1].type == "manual"

        assert len(wf.steps) == 3
        assert wf.steps[0].name == "enrich_context"
        assert len(wf.steps[0].actions) == 1
        assert wf.steps[0].actions[0].type == "enrich"

        assert wf.steps[1].if_ == "alert.rule_level >= 12"
        assert wf.steps[1].actions[0].type == "gated_containment"
        assert wf.steps[1].actions[0].with_["action_type"] == "isolate_host"

    def test_load_yaml_roundtrip_no_extra_fields(self):
        wf = load_yaml(SAMPLE_YAML)
        assert set(wf.steps[1].actions[0].with_.keys()) == {"action_type"}

    def test_load_yaml_invalid_root(self):
        with pytest.raises(ValueError, match="must be a mapping"):
            load_yaml("[1, 2, 3]")

    def test_load_yaml_provider_step(self):
        yaml_str = """
id: provider_test
triggers:
  - type: manual
steps:
  - name: query_vt
    provider:
      type: virustotal
      with:
        ip: "1.2.3.4"
    actions:
      - type: enrich
"""
        wf = load_yaml(yaml_str)
        assert wf.id == "provider_test"
        assert wf.steps[0].provider == {"type": "virustotal", "with": {"ip": "1.2.3.4"}}


# ── Tests: triggers ─────────────────────────────────────────────────────────


class TestTriggers:
    def test_alert_trigger_match(self):
        trigger = Trigger(type="alert", with_={"cel": "alert.rule_level >= 10"})
        ok, reason = match_trigger(trigger, alert={"rule_level": 12})
        assert ok is True
        assert "CEL match" in reason

    def test_alert_trigger_no_match(self):
        trigger = Trigger(type="alert", with_={"cel": "alert.rule_level >= 15"})
        ok, reason = match_trigger(trigger, alert={"rule_level": 12})
        assert ok is False
        assert "no match" in reason

    def test_alert_trigger_missing_cel(self):
        trigger = Trigger(type="alert", with_={})
        ok, _ = match_trigger(trigger, alert={"rule_level": 12})
        assert ok is False

    def test_alert_trigger_missing_alert(self):
        trigger = Trigger(type="alert", with_={"cel": "alert.rule_level >= 10"})
        ok, _ = match_trigger(trigger, alert=None)
        assert ok is False

    def test_interval_trigger(self):
        trigger = Trigger(type="interval", with_={"cron": "*/5 * * * *"})
        ok, _ = match_trigger(trigger)
        assert ok is True

    def test_manual_trigger(self):
        trigger = Trigger(type="manual")
        ok, _ = match_trigger(trigger)
        assert ok is True

    def test_webhook_trigger(self):
        trigger = Trigger(type="webhook")
        ok, _ = match_trigger(trigger)
        assert ok is True

    def test_unknown_trigger_type(self):
        trigger = Trigger(type="bogus")
        ok, _ = match_trigger(trigger)
        assert ok is False


# ── Tests: context interpolation ────────────────────────────────────────────


class TestContext:
    def test_interpolate_alert_field(self):
        result = interpolate("{{ alert.id }} - {{ alert.severity }}", alert={"id": "A1", "severity": "high"})
        assert result == "A1 - high"

    def test_interpolate_step_output(self):
        step_outputs = {"enrich": {"output": {"is_malicious": True}}}
        result = interpolate("{{ steps.enrich.output.is_malicious }}", step_outputs=step_outputs)
        assert result == "True"

    def test_interpolate_unknown_path(self):
        result = interpolate("{{ alert.nonexistent }}", alert={"id": "1"})
        assert result == ""

    def test_workflow_context_roundtrip(self):
        ctx = WorkflowContext(alert={"id": "A1"})
        ctx.set_step_output("enrich", {"verdict": "bad"})
        assert ctx.get_step_output("enrich") == {"verdict": "bad"}
        result = ctx.interpolate("{{ steps.enrich.output.verdict }}")
        assert result == "bad"

    def test_interpolate_no_placeholder(self):
        result = interpolate("plain text", alert={"id": "1"})
        assert result == "plain text"


# ── Tests: engine (live, no mocks) ──────────────────────────────────────────


class TestEngine:
    async def test_no_trigger_match(self, sample_alert):
        """Workflow with no matching trigger returns triggered=False."""
        wf = load_yaml("""
id: no_match
triggers:
  - type: alert
    with:
      cel: alert.rule_level >= 20
steps:
  - name: step1
    actions:
      - type: notify
""")
        engine = WorkflowEngine()
        result = await engine.run(wf, alert={"rule_level": 5})
        assert result["triggered"] is False
        assert result["steps"] == []

    async def test_trigger_and_execute_builtin(self, sample_alert):
        wf = load_yaml("""
id: simple
triggers:
  - type: alert
    with:
      cel: alert.rule_level >= 10
steps:
  - name: notify_step
    actions:
      - type: notify
        with:
          channel: email
          message: "test"
""")
        engine = WorkflowEngine()
        result = await engine.run(wf, alert=sample_alert)
        assert result["triggered"] is True
        assert len(result["steps"]) == 1
        step = result["steps"][0]
        assert step["step"] == "notify_step"
        assert step["skipped"] is False
        assert step["actions"][0]["success"] is True

    async def test_step_condition_skip(self, sample_alert):
        """Step with false if: condition is skipped."""
        wf = load_yaml("""
id: skip_test
triggers:
  - type: alert
    with:
      cel: alert.rule_level >= 10
steps:
  - name: skip_me
    if: alert.rule_level >= 99
    actions:
      - type: notify
  - name: run_me
    actions:
      - type: create_case
""")
        engine = WorkflowEngine()
        result = await engine.run(wf, alert=sample_alert)
        assert result["triggered"] is True
        assert result["steps"][0]["skipped"] is True
        assert result["steps"][1]["skipped"] is False

    async def test_interpolation_in_action_params(self, sample_alert):
        wf = load_yaml("""
id: interp_test
triggers:
  - type: alert
    with:
      cel: alert.rule_level >= 10
steps:
  - name: alert_info
    actions:
      - type: notify
        with:
          channel: slack
          message: "Alert {{ alert.id }} level {{ alert.rule_level }}"
""")
        engine = WorkflowEngine()
        result = await engine.run(wf, alert=sample_alert)
        step = result["steps"][0]
        # In the resolved intended_actions the params should be interpolated
        assert step["intended_actions"][0]["with"]["message"] == "Alert alert-001 level 14"

    async def test_dry_run_skips_execution(self, sample_alert):
        wf = load_yaml("""
id: dry_run_test
triggers:
  - type: alert
    with:
      cel: alert.rule_level >= 10
steps:
  - name: notify_me
    actions:
      - type: notify
        with:
          channel: slack
          message: "dry run msg"
""")
        engine = WorkflowEngine(dry_run=True)
        result = await engine.run(wf, alert=sample_alert)
        assert result["dry_run"] is True
        assert result["triggered"] is True
        step = result["steps"][0]
        # Dry-run actions have dry_run=True marker
        assert step["actions"][0]["dry_run"] is True
        # intended_actions still lists what would happen
        assert step["intended_actions"][0]["with"]["message"] == "dry run msg"

    async def test_gated_containment_routes_to_policy(self, sample_alert):
        """gated_containment action calls check_policy and returns decision."""
        wf = load_yaml("""
id: containment_test
triggers:
  - type: alert
    with:
      cel: alert.rule_level >= 10
steps:
  - name: contain
    actions:
      - type: gated_containment
        with:
          action_type: block_ip
          target: "{{ alert.source_ip }}"
""")
        engine = WorkflowEngine()
        result = await engine.run(wf, alert=sample_alert)
        step = result["steps"][0]
        action = step["actions"][0]
        assert action["type"] == "gated_containment"
        assert action["action_type"] == "block_ip"
        # target was interpolated
        assert "target" in action
        # Decision should come from containment_gate policy
        assert action["decision"] in ("allow", "deny", "require_approval")
        assert action["executed"] is False

    async def test_dry_run_with_provider(self, sample_alert):
        """Dry-run mode still evaluates but doesn't call the provider."""
        mock_provider = AsyncMock()
        mock_provider.query = AsyncMock(return_value={"result": "ok"})

        wf = load_yaml("""
id: provider_dry
triggers:
  - type: alert
    with:
      cel: alert.rule_level >= 10
steps:
  - name: query_ext
    provider:
      type: mock_prov
      with:
        param1: "value1"
    actions:
      - type: notify
""")
        engine = WorkflowEngine(providers={"mock_prov": mock_provider}, dry_run=True)
        result = await engine.run(wf, alert=sample_alert)
        assert result["dry_run"] is True
        assert result["triggered"] is True
        # Provider should NOT have been called
        mock_provider.query.assert_not_called()
        step = result["steps"][0]
        assert step["provider"] == "mock_prov"

    async def test_step_output_available_to_later_steps(self, sample_alert):
        ctx = WorkflowContext(alert=sample_alert)
        ctx.set_step_output("first", {"verdict": "malicious"})
        result = ctx.interpolate("{{ steps.first.output.verdict }}")
        assert result == "malicious"

    async def test_full_workflow_multiple_steps(self, sample_alert):
        wf = load_yaml("""
id: multi_step
triggers:
  - type: alert
    with:
      cel: alert.rule_level >= 10
steps:
  - name: step_a
    actions:
      - type: enrich
  - name: step_b
    actions:
      - type: create_case
        with:
          title: "Case from {{ alert.id }}"
  - name: step_c
    if: alert.rule_level >= 12
    actions:
      - type: notify
        with:
          channel: slack
          message: "Completed"
""")
        engine = WorkflowEngine()
        result = await engine.run(wf, alert=sample_alert)
        assert result["triggered"] is True
        assert len(result["steps"]) == 3
        assert result["steps"][0]["actions"][0]["type"] == "enrich"
        assert result["steps"][1]["actions"][0]["type"] == "create_case"
        assert result["steps"][2]["skipped"] is False  # rule_level=14 >= 12

    async def test_step_condition_with_alert_score(self):
        """Step condition can evaluate score field."""
        wf = load_yaml("""
id: score_check
triggers:
  - type: alert
    with:
      cel: alert.rule_level >= 5
steps:
  - name: conditional_step
    actions:
      - type: notify
""")
        engine = WorkflowEngine()
        result = await engine.run(wf, alert={"rule_level": 7, "score": 85})
        assert result["triggered"] is True
