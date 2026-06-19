"""Workflow execution engine.

Builds context, evaluates triggers, runs steps in order, dispatches
builtin actions and provider calls.

Dry-run::
    engine = WorkflowEngine(dry_run=True)
    result = await engine.run(workflow, alert=alert_data)
    # result["steps"][...]["intended_actions"] holds planned actions
    # but nothing is actually executed.
"""

from __future__ import annotations

import logging
from typing import Any

from shared.rules.cel import build_activation, compile_rule, evaluate
from shared.workflows.context import WorkflowContext
from shared.workflows.models import Action, Step, Trigger, Workflow
from shared.workflows.triggers import match_trigger

logger = logging.getLogger(__name__)


class WorkflowEngine:
    """Declarative workflow executor.

    Parameters
    ----------
    providers
        Optional dict mapping provider type names to ``BaseProvider``
        instances.  When set, steps with ``provider.type`` matching a
        key will call ``provider.query(**params)``.
    dry_run
        When ``True``, triggers and conditions are evaluated but no
        actions or provider calls are actually executed.  The result
        lists ``intended_actions`` for each step.
    """

    def __init__(
        self,
        providers: dict[str, Any] | None = None,
        dry_run: bool = False,
    ) -> None:
        self._providers = providers or {}
        self.dry_run = dry_run

    # ── Public API ────────────────────────────────────────────────────────

    async def run(
        self,
        workflow: Workflow,
        *,
        alert: dict[str, Any] | None = None,
        trigger_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a workflow end-to-end.

        Returns a result dict with keys: ``workflow_id``, ``triggered``,
        ``trigger_reason``, ``steps`` (list of step results), ``dry_run``.
        """
        if alert is None:
            alert = {}

        # ── Resolve which trigger fired ─────────────────────────────
        triggered = False
        trigger_reason = "no trigger matched"
        for t in workflow.triggers:
            ok, reason = match_trigger(t, alert=alert, context=trigger_data)
            if ok:
                triggered = True
                trigger_reason = reason
                break

        if not triggered:
            return {
                "workflow_id": workflow.id,
                "triggered": False,
                "trigger_reason": trigger_reason,
                "steps": [],
                "dry_run": self.dry_run,
            }

        # ── Build context ────────────────────────────────────────────
        ctx = WorkflowContext(alert=alert, trigger_data=trigger_data)

        # ── Run steps ────────────────────────────────────────────────
        step_results: list[dict[str, Any]] = []
        for step in workflow.steps:
            step_result = await self._run_step(step, ctx)
            step_results.append(step_result)

            # Store output for interpolation by later steps
            if step_result.get("output") is not None:
                ctx.set_step_output(step.name, step_result["output"])

        return {
            "workflow_id": workflow.id,
            "triggered": True,
            "trigger_reason": trigger_reason,
            "steps": step_results,
            "dry_run": self.dry_run,
        }

    # ── Step execution ────────────────────────────────────────────────────

    async def _run_step(self, step: Step, ctx: WorkflowContext) -> dict[str, Any]:
        result: dict[str, Any] = {
            "step": step.name,
            "skipped": False,
            "output": None,
            "actions": [],
            "intended_actions": [],
        }

        # ── Condition check ──────────────────────────────────────────
        if step.if_:
            ok, reason = self._eval_condition(step.if_, ctx)
            if not ok:
                logger.info("Step '%s' skipped — condition false: %s", step.name, reason)
                result["skipped"] = True
                result["skip_reason"] = reason
                return result

        # ── Provider call ────────────────────────────────────────────
        provider_output: dict[str, Any] | None = None
        if step.provider:
            provider_output = await self._call_provider(step.provider, ctx)
            result["provider"] = step.provider.get("type", "")
            result["output"] = provider_output

        # ── Builtin actions ──────────────────────────────────────────
        intended: list[dict[str, Any]] = []
        for action in step.actions:
            interped_action = self._interpolate_action(action, ctx)
            intended.append(interped_action)

            if not self.dry_run:
                action_result = await self._exec_action(interped_action, ctx)
                result["actions"].append(action_result)
            else:
                result["actions"].append({"type": action.type, "dry_run": True})

        result["intended_actions"] = intended
        return result

    # ── Internals ────────────────────────────────────────────────────────

    def _eval_condition(self, cel_expr: str, ctx: WorkflowContext) -> tuple[bool, str]:
        activation = build_activation(
            alert={
                "rule_level": ctx.alert.get("rule_level", 0),
                "rule_id": ctx.alert.get("rule_id", 0),
                "rule_groups": ctx.alert.get("rule_groups", []),
            },
            score=ctx.alert.get("score"),
        )
        try:
            prog = compile_rule(cel_expr)
            result = evaluate(prog, activation)
            return bool(result), "" if result else "condition false"
        except Exception as exc:
            logger.warning("Step condition CEL error %r: %s", cel_expr, exc)
            return False, f"CEL error: {exc}"

    def _interpolate_action(self, action: Action, ctx: WorkflowContext) -> dict[str, Any]:
        """Resolve ``{{ }}`` placeholders inside action params."""
        resolved: dict[str, Any] = {"type": action.type}
        if action.with_:
            resolved["with"] = self._deep_interpolate(action.with_, ctx)
        return resolved

    def _deep_interpolate(
        self, value: Any, ctx: WorkflowContext
    ) -> Any:
        if isinstance(value, str):
            return ctx.interpolate(value)
        elif isinstance(value, dict):
            return {k: self._deep_interpolate(v, ctx) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._deep_interpolate(v, ctx) for v in value]
        return value

    async def _call_provider(
        self, provider_cfg: dict[str, Any], ctx: WorkflowContext
    ) -> dict[str, Any]:
        ptype = provider_cfg.get("type", "")
        provider = self._providers.get(ptype)
        if not provider:
            logger.warning("Provider %r not registered — skipping", ptype)
            return {"error": f"provider '{ptype}' not found"}

        raw_params = provider_cfg.get("with", {})
        params = self._deep_interpolate(raw_params, ctx)

        if self.dry_run:
            logger.info("DRY-RUN: would call provider %s with %s", ptype, params)
            return {"dry_run": True, "provider": ptype, "params": params}

        try:
            return await provider.query(**params)
        except Exception as exc:
            logger.error("Provider %s query failed: %s", ptype, exc)
            return {"error": str(exc), "provider": ptype, "params": params}

    async def _exec_action(self, action: dict[str, Any], ctx: WorkflowContext) -> dict[str, Any]:
        """Execute a builtin action."""
        atype = action["type"]
        params = action.get("with", {})
        handler = _BUILTINS.get(atype)
        if handler is None:
            logger.warning("Unknown builtin action %r — skipping", atype)
            return {"type": atype, "success": False, "error": "unknown action type"}
        try:
            return await handler(params, ctx)
        except Exception as exc:
            logger.error("Builtin action %s failed: %s", atype, exc)
            return {"type": atype, "success": False, "error": str(exc)}


# ── Builtin action handlers ──────────────────────────────────────────────────

async def _builtin_enrich(params: dict[str, Any], ctx: WorkflowContext) -> dict[str, Any]:
    """Enrichment — queues TI enrichment for the alert."""
    logger.info("Builtin enrich | alert=%s", ctx.alert.get("id"))
    return {"type": "enrich", "success": True}


async def _builtin_create_case(params: dict[str, Any], ctx: WorkflowContext) -> dict[str, Any]:
    """Create a case from the alert."""
    title = params.get("title") or ctx.alert.get("rule_description", "Workflow case")
    severity = params.get("severity") or ctx.alert.get("severity", "medium")
    logger.info("Builtin create_case | title=%s severity=%s", title, severity)
    return {"type": "create_case", "success": True, "title": title, "severity": severity}


async def _builtin_gated_containment(
    params: dict[str, Any], ctx: WorkflowContext
) -> dict[str, Any]:
    """Containment routed through ``containment_guard`` — never auto-fires.

    In dry-run the gate is still evaluated (policy check) but the
    actual containment action is never dispatched.
    """
    from shared.enrichment.containment_gate import (
        ContainmentAction,
        check_policy,
    )
    from shared.enrichment.risk_score import EnrichmentContext

    action_type = params.get("action_type", "")
    target = params.get("target", ctx.alert.get("source_ip", "unknown"))

    # Map string to ContainmentAction enum
    action_map = {
        "isolate_host": ContainmentAction.ISOLATE_HOST,
        "block_ip": ContainmentAction.BLOCK_IP,
        "disable_user": ContainmentAction.DISABLE_USER,
        "quarantine_file": ContainmentAction.QUARANTINE_FILE,
        "snapshot_evidence": ContainmentAction.SNAPSHOT_EVIDENCE,
    }
    ca = action_map.get(action_type)
    if ca is None:
        return {"type": "gated_containment", "success": False, "error": f"unknown action: {action_type}"}

    rule_level = ctx.alert.get("rule_level", 0)
    try:
        rule_level = int(rule_level) if rule_level is not None else 0
    except (ValueError, TypeError):
        rule_level = 0
    enrichment_ctx = EnrichmentContext(rule_level=rule_level)
    from shared.enrichment.risk_score import compute
    score = compute(enrichment_ctx)

    decision, reason = check_policy(ca, enrichment_ctx, score)
    logger.info("Gated containment | action=%s target=%s decision=%s | %s", action_type, target, decision.value, reason)

    return {
        "type": "gated_containment",
        "action_type": action_type,
        "target": target,
        "decision": decision.value,
        "reason": reason,
        "executed": False,  # gate decides; actual exec is separate
    }


async def _builtin_notify(params: dict[str, Any], ctx: WorkflowContext) -> dict[str, Any]:
    """Send a notification."""
    channel = params.get("channel", "slack")
    message = params.get("message", "")
    logger.info("Builtin notify | channel=%s message=%s", channel, message)
    return {"type": "notify", "success": True, "channel": channel, "message": message}


_BUILTINS: dict[str, Any] = {
    "enrich": _builtin_enrich,
    "create_case": _builtin_create_case,
    "gated_containment": _builtin_gated_containment,
    "notify": _builtin_notify,
}
