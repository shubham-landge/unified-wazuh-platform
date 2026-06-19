"""Workflow trigger matchers — alert, interval, manual, webhook.

Usage::

    from shared.workflows.triggers import match_trigger, compile_all_triggers

    ok, _ = match_trigger(trigger, alert=alert_data)
    ok, _ = match_trigger(trigger, context={"headers": {...}})
"""

from __future__ import annotations

import logging
from typing import Any

from shared.rules.cel import build_activation, compile_rule, evaluate
from shared.workflows.models import Trigger

__all__ = ["match_trigger"]

logger = logging.getLogger(__name__)


def match_trigger(
    trigger: Trigger,
    *,
    alert: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Evaluate whether a trigger fires given the current signal.

    Returns ``(match: bool, reason: str)``.

    Trigger type behaviour
    ----------------------
    * ``alert`` — evaluates the ``cel`` expression in ``trigger.with_``
      against the alert activation map.
    * ``interval`` — the scheduler decides when to fire; the matcher
      always returns ``True`` (the caller is responsible for cron).
    * ``manual`` — always matches when called (human triggered).
    * ``webhook`` — always matches when called (caller decides routing).
    """
    ttype = trigger.type
    params = trigger.with_

    if ttype == "alert":
        return _match_alert_trigger(params, alert)
    elif ttype == "interval":
        # The ARQ/APScheduler layer decides when to invoke; once called
        # the workflow always runs.
        return True, "interval trigger — always fires when scheduled"
    elif ttype == "manual":
        return True, "manual trigger"
    elif ttype == "webhook":
        return True, "webhook trigger"
    else:
        logger.warning("Unknown trigger type %r — defaulting to no match", ttype)
        return False, f"unknown trigger type: {ttype}"


def _match_alert_trigger(
    params: dict[str, Any], alert: dict[str, Any] | None
) -> tuple[bool, str]:
    cel_expr = params.get("cel")
    if not cel_expr:
        return False, "alert trigger missing 'cel' expression"

    if alert is None:
        return False, "no alert data provided"

    activation = build_activation(
        alert={
            "rule_level": alert.get("rule_level", 0),
            "rule_id": alert.get("rule_id", 0),
            "rule_groups": alert.get("rule_groups", []),
        },
        ti=alert.get("ti"),
        ueba=alert.get("ueba"),
        asset=alert.get("asset"),
        geo=alert.get("geo"),
        vuln=alert.get("vuln"),
        score=alert.get("score"),
    )

    try:
        prog = compile_rule(cel_expr)
        result = evaluate(prog, activation)
        if result:
            return True, f"CEL match: {cel_expr}"
        return False, f"CEL no match: {cel_expr}"
    except Exception as exc:
        logger.warning("CEL evaluation error for %r: %s", cel_expr, exc)
        return False, f"CEL error: {exc}"
