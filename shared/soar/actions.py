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
from sqlalchemy import select

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


async def _identity_disable_user(action: dict, ctx: ActionContext) -> dict:
    from shared.orchestrator.handlers import containment_guard
    from shared.models.alert import Alert

    user_id = action.get("user_id")
    if not user_id:
        return {"success": False, "error": "user_id required"}

    tenant_id = None
    alert_id = ctx.alert.get("id")
    if alert_id:
        res = await ctx.session.execute(select(Alert).where(Alert.id == uuid.UUID(str(alert_id))))
        alert = res.scalar_one_or_none()
        if alert:
            tenant_id = alert.tenant_id

    guard = await containment_guard(
        ctx.session,
        tenant_id,
        "disable_user",
        {"user_id": user_id, "alert_id": alert_id},
        rationale=f"SOAR requested disabling user {user_id} for alert {alert_id}",
        risk_level="high",
    )
    if not guard["approved"]:
        logger.warning("disable_user gated pending approval %s", guard.get("approval_id"))
        return {"success": False, "requires_approval": True, "approval_id": guard.get("approval_id"), "error": guard["reason"]}

    from shared.soar.actions_identity import disable_user
    return await disable_user(user_id, reason=action.get("reason"), graph_token=action.get("graph_token"))


async def _identity_revoke_sessions(action: dict, ctx: ActionContext) -> dict:
    from shared.orchestrator.handlers import containment_guard
    from shared.models.alert import Alert

    user_id = action.get("user_id")
    if not user_id:
        return {"success": False, "error": "user_id required"}

    tenant_id = None
    alert_id = ctx.alert.get("id")
    if alert_id:
        res = await ctx.session.execute(select(Alert).where(Alert.id == uuid.UUID(str(alert_id))))
        alert = res.scalar_one_or_none()
        if alert:
            tenant_id = alert.tenant_id

    guard = await containment_guard(
        ctx.session,
        tenant_id,
        "revoke_sessions",
        {"user_id": user_id, "alert_id": alert_id},
        rationale=f"SOAR requested revoking sessions for user {user_id}",
        risk_level="high",
    )
    if not guard["approved"]:
        return {"success": False, "requires_approval": True, "approval_id": guard.get("approval_id"), "error": guard["reason"]}

    from shared.soar.actions_identity import revoke_sessions
    return await revoke_sessions(user_id, graph_token=action.get("graph_token"))


async def _identity_block_ip(action: dict, ctx: ActionContext) -> dict:
    from shared.orchestrator.handlers import containment_guard
    from shared.models.alert import Alert

    ip_address = action.get("ip_address")
    if not ip_address:
        return {"success": False, "error": "ip_address required"}

    tenant_id = None
    alert_id = ctx.alert.get("id")
    if alert_id:
        res = await ctx.session.execute(select(Alert).where(Alert.id == uuid.UUID(str(alert_id))))
        alert = res.scalar_one_or_none()
        if alert:
            tenant_id = alert.tenant_id

    guard = await containment_guard(
        ctx.session,
        tenant_id,
        "block_ip",
        {"ip_address": ip_address, "alert_id": alert_id},
        rationale=f"SOAR requested blocking IP {ip_address}",
        risk_level="medium",
    )
    if not guard["approved"]:
        return {"success": False, "requires_approval": True, "approval_id": guard.get("approval_id"), "error": guard["reason"]}

    from shared.soar.actions_identity import block_ip
    return await block_ip(ip_address, reason=action.get("reason"))


_REGISTRY = {
    "create_case":          _create_case,
    "webhook":              _webhook,
    "wait":                 _wait,
    "notify":               _notify,
    "enrich_threat_intel":  _enrich_threat_intel,
    "set_severity":         _set_severity,
    "log":                  _log,
    "disable_user":         _identity_disable_user,
    "revoke_sessions":      _identity_revoke_sessions,
    "block_ip":             _identity_block_ip,
}
