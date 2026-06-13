"""
SOAR action executors.

Each action is a dict with a required "type" key.
Actions run in order; a failed action with "continue_on_error": false halts the playbook.
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)


class ActionContext:
    """Shared context passed to every action in a playbook run."""
    def __init__(self, alert: dict, session, redis_client, case_id: str | None = None):
        self.alert = alert
        self.session = session
        self.redis_client = redis_client
        self.case_id = case_id
        self.results: list[dict] = []


async def execute_action(action: dict, ctx: ActionContext) -> dict:
    action_type = action.get("type", "")
    handler = _REGISTRY.get(action_type)
    if not handler:
        return {"success": False, "error": f"Unknown action type: {action_type}"}
    try:
        return await handler(action, ctx)
    except Exception as e:
        logger.error("Action %s failed: %s", action_type, e, exc_info=True)
        return {"success": False, "error": str(e)}


async def _create_case(action: dict, ctx: ActionContext) -> dict:
    from shared.models.case import Case
    from shared.models.case_investigation_step import CaseInvestigationStep
    from shared.models.case_event import CaseEvent

    risk_score = action.get("risk_score")
    if risk_score is None:
        level = ctx.alert.get("rule_level", 5)
        confidence = action.get("confidence", 0.5)
        fp_likelihood = action.get("false_positive_likelihood", 0.3)
        risk_score = round(confidence * (1 - fp_likelihood) * min(level / 15, 1) * 10, 2)

    case = Case(
        alert_id=ctx.alert.get("id"),
        title=action.get("title") or ctx.alert.get("rule_description", "Playbook case"),
        severity=action.get("severity") or ctx.alert.get("severity", "medium"),
        category=action.get("category", "playbook"),
        description=action.get("description"),
        assigned_to=action.get("assigned_to"),
        escalation_required=action.get("escalation_required", False),
        risk_score=risk_score,
    )
    ctx.session.add(case)
    await ctx.session.flush()
    ctx.case_id = str(case.id)

    for i, step_text in enumerate(action.get("investigation_steps", [])):
        step = CaseInvestigationStep(
            case_id=case.id,
            description=step_text,
            order=i,
        )
        ctx.session.add(step)

    event = CaseEvent(
        case_id=case.id,
        event_type="case_created",
        description=f"SOAR playbook case: {case.title}",
        event_meta={"playbook": ctx.alert.get("playbook_name")},
    )
    ctx.session.add(event)

    logger.info("SOAR created case %s (risk=%.2f, steps=%d)", case.id, risk_score, len(action.get("investigation_steps", [])))
    return {"success": True, "case_id": str(case.id)}


async def _webhook(action: dict, ctx: ActionContext) -> dict:
    url = action.get("url")
    if not url:
        return {"success": False, "error": "webhook action missing 'url'"}

    method = action.get("method", "POST").upper()
    payload = action.get("payload") or {
        "alert": ctx.alert,
        "case_id": ctx.case_id,
        "playbook_action": "webhook",
    }
    headers = action.get("headers", {"Content-Type": "application/json"})
    timeout = action.get("timeout", 15)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await getattr(client, method.lower())(url, json=payload, headers=headers)
            resp.raise_for_status()
        logger.info("SOAR webhook %s %s → %d", method, url, resp.status_code)
        return {"success": True, "status_code": resp.status_code}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def _wait(action: dict, ctx: ActionContext) -> dict:
    seconds = float(action.get("seconds", 0))
    if seconds > 0:
        logger.debug("SOAR wait %.1fs", seconds)
        await asyncio.sleep(min(seconds, 300))   # cap at 5 min to prevent runaway playbooks
    return {"success": True, "waited_seconds": seconds}


async def _notify(action: dict, ctx: ActionContext) -> dict:
    """Enqueue a notification job onto the notification queue."""
    channel = action.get("channel", "slack")
    job = {
        "channel": channel,
        "alert": ctx.alert,
        "payload": action.get("payload", {}),
    }
    if ctx.redis_client:
        await ctx.redis_client.lpush("notification_queue", json.dumps(job))
        logger.info("SOAR queued %s notification for alert %s", channel, ctx.alert.get("id"))
    return {"success": True, "channel": channel}


async def _enrich_threat_intel(action: dict, ctx: ActionContext) -> dict:
    """Push the alert onto the TI enrichment queue."""
    alert_id = ctx.alert.get("id")
    if ctx.redis_client and alert_id:
        await ctx.redis_client.lpush("ti_enrich_queue", json.dumps({"alert_id": str(alert_id)}))
        logger.info("SOAR queued TI enrichment for alert %s", alert_id)
    return {"success": True}


async def _set_severity(action: dict, ctx: ActionContext) -> dict:
    severity = action.get("severity")
    if severity:
        ctx.alert["severity"] = severity
    return {"success": True, "severity": severity}


async def _log(action: dict, ctx: ActionContext) -> dict:
    logger.info("SOAR log: %s | alert=%s", action.get("message", ""), ctx.alert.get("id"))
    return {"success": True}


_REGISTRY = {
    "create_case":          _create_case,
    "webhook":              _webhook,
    "wait":                 _wait,
    "notify":               _notify,
    "enrich_threat_intel":  _enrich_threat_intel,
    "set_severity":         _set_severity,
    "log":                  _log,
}
