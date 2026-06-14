"""Agent handler implementations for the orchestration engine."""

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import desc, select

from shared.config import settings
from shared.connectors.llm_provider import get_provider
from shared.models.alert import Alert
from shared.models.case import Case
from shared.models.ueba import UebaAnomaly
from shared.orchestrator.engine import HandlerContext

logger = logging.getLogger(__name__)


async def _load_alert(session, alert_id: str | uuid.UUID) -> Alert | None:
    try:
        if isinstance(alert_id, str):
            alert_id = uuid.UUID(alert_id)
        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        return result.scalar_one_or_none()
    except Exception as exc:
        logger.warning("Failed to load alert %s: %s", alert_id, exc)
        return None


async def triage(input_data: dict, ctx: HandlerContext) -> dict:
    """Triage an alert using the configured LLM provider."""
    alert_id = input_data.get("alert_id")
    if not alert_id:
        raise ValueError("alert_id is required for triage handler")

    alert = await _load_alert(ctx.session, alert_id)
    if not alert:
        raise ValueError(f"Alert {alert_id} not found")

    alert_dict = {
        "id": str(alert.id),
        "title": getattr(alert, "title", None),
        "description": getattr(alert, "description", None),
        "severity": getattr(alert, "severity", None),
        "rule_level": getattr(alert, "rule_level", None),
        "agent_id": getattr(alert, "agent_id", None),
        "agent_ip": getattr(alert, "agent_ip", None),
        "source_ip": getattr(alert, "source_ip", None),
        "user_name": getattr(alert, "user_name", None),
        "mitre_technique": getattr(alert, "mitre_technique", None),
        "mitre_tactic": getattr(alert, "mitre_tactic", None),
    }

    system_prompt = (
        "You are an expert SOC analyst. Analyze the security alert below and return a JSON object "
        "with exactly these keys: verdict (malicious|suspicious|benign), severity (critical|high|medium|low), "
        "confidence (0.0-1.0), summary (string), recommended_action (string)."
    )
    user_prompt = json.dumps(alert_dict, default=str)

    provider = get_provider()
    result = await provider.analyze(system_prompt, user_prompt)
    if not result.get("success"):
        raise RuntimeError(result.get("error", "LLM analysis failed"))

    return {
        "verdict": result.get("verdict", "suspicious"),
        "severity": result.get("severity", alert_dict.get("severity") or "medium"),
        "confidence": float(result.get("confidence", 0.5)),
        "summary": result.get("summary", ""),
        "recommended_action": result.get("recommended_action", ""),
        "alert_id": str(alert.id),
        "model": result.get("model"),
    }


async def ti_enrich(input_data: dict, ctx: HandlerContext) -> dict:
    """Enrich IOCs from threat intel feeds (OTX, MISP, VirusTotal)."""
    iocs = input_data.get("iocs") or []
    if not iocs:
        raise ValueError("iocs list is required for ti_enrich handler")

    if isinstance(iocs, dict):
        iocs = [iocs]

    from shared.connectors.ti_alienvault import AlienVaultOTXConnector
    from shared.connectors.ti_misp import MISPConnector
    from shared.connectors.ti_virustotal import VirusTotalConnector

    otx = AlienVaultOTXConnector()
    misp = MISPConnector()
    vt = VirusTotalConnector()

    enrichment = []
    for ioc in iocs:
        ioc_type = ioc.get("type", "ip")
        value = ioc.get("value")
        if not value:
            continue

        otx_result = await otx.lookup(ioc_type, value)
        misp_result = await misp.lookup(ioc_type, value)
        vt_result = await vt.lookup(ioc_type, value) if settings.virustotal_api_key else {}

        enrichment.append(
            {
                "ioc": value,
                "type": ioc_type,
                "otx": otx_result,
                "misp": misp_result,
                "virustotal": vt_result,
            }
        )

    return {"enrichment": enrichment, "count": len(enrichment)}


async def ueba_check(input_data: dict, ctx: HandlerContext) -> dict:
    """Check UEBA anomaly history for a subject (user, ip, agent)."""
    subject_type = input_data.get("subject_type")
    subject_id = input_data.get("subject_id")
    if not subject_type or not subject_id:
        raise ValueError("subject_type and subject_id are required for ueba_check handler")

    result = await ctx.session.execute(
        select(UebaAnomaly)
        .where(
            UebaAnomaly.subject_type == subject_type,
            UebaAnomaly.subject_id == subject_id,
        )
        .order_by(desc(UebaAnomaly.created_at))
        .limit(10)
    )
    anomalies = result.scalars().all()

    anomaly_list = [
        {
            "id": str(a.id),
            "type": a.anomaly_type,
            "score": float(a.score) if a.score else 0.0,
            "severity": a.severity,
            "description": a.description,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in anomalies
    ]

    max_score = max((a["score"] for a in anomaly_list), default=0.0)
    risk_level = "low"
    if max_score >= 5.0:
        risk_level = "critical"
    elif max_score >= 3.5:
        risk_level = "high"
    elif max_score >= 2.5:
        risk_level = "medium"

    return {
        "subject_type": subject_type,
        "subject_id": subject_id,
        "risk_level": risk_level,
        "max_score": max_score,
        "anomalies": anomaly_list,
    }


async def case_create(input_data: dict, ctx: HandlerContext) -> dict:
    """Create a Case record from agent input."""
    title = input_data.get("title")
    if not title:
        raise ValueError("title is required for case_create handler")

    alert_id = input_data.get("alert_id")
    case = Case(
        tenant_id=ctx.run.tenant_id,
        title=title,
        description=input_data.get("description", ""),
        severity=input_data.get("severity", "medium"),
        status="open",
        category=input_data.get("category", "agent_generated"),
        alert_id=uuid.UUID(alert_id) if alert_id else None,
        risk_score=float(input_data.get("risk_score", 0.0)),
    )
    ctx.session.add(case)
    await ctx.session.flush()

    return {
        "case_id": str(case.id),
        "title": case.title,
        "severity": case.severity,
        "status": case.status,
        "alert_id": alert_id,
    }


async def soar_run(input_data: dict, ctx: HandlerContext) -> dict:
    """Execute SOAR playbooks against an alert."""
    from shared.soar.engine import SOAREngine

    alert = input_data.get("alert") or {}
    alert_id = input_data.get("alert_id")

    if alert_id and not alert:
        db_alert = await _load_alert(ctx.session, alert_id)
        if db_alert:
            alert = {
                "id": str(db_alert.id),
                "title": getattr(db_alert, "title", ""),
                "description": getattr(db_alert, "description", ""),
                "severity": getattr(db_alert, "severity", ""),
                "rule_level": getattr(db_alert, "rule_level", None),
                "agent_id": getattr(db_alert, "agent_id", None),
                "source_ip": getattr(db_alert, "source_ip", None),
                "user_name": getattr(db_alert, "user_name", None),
            }

    if not alert:
        raise ValueError("alert or alert_id is required for soar_run handler")

    engine = SOAREngine(session=ctx.session)
    results = await engine.run_for_alert(alert)
    return {"playbook_runs": results}


async def notify(input_data: dict, ctx: HandlerContext) -> dict:
    """Send a notification via email, Slack, or Teams."""
    from shared.connectors.notify_email import EmailConnector
    from shared.connectors.notify_slack import SlackConnector
    from shared.connectors.notify_teams import TeamsConnector

    channel = input_data.get("channel", "email")
    message = input_data.get("message", "")
    recipients = input_data.get("recipients", [])
    subject = input_data.get("subject", "SOC Notification")

    if isinstance(recipients, str):
        recipients = [r.strip() for r in recipients.split(",") if r.strip()]

    if channel == "email":
        connector = EmailConnector()
        result = await connector.send(
            to=recipients,
            subject=subject,
            body_html=message,
        )
    elif channel == "slack":
        connector = SlackConnector()
        result = await connector.send(text=message, channel=None)
    elif channel == "teams":
        connector = TeamsConnector()
        result = await connector.send(title=subject, summary=message)
    else:
        raise ValueError(f"Unsupported notification channel: {channel}")

    return {
        "channel": channel,
        "success": result.get("success", False),
        "error": result.get("error"),
        "recipients": recipients,
    }


async def review(input_data: dict, ctx: HandlerContext) -> dict:
    """Peer-review a previous agent output."""
    output = input_data.get("output") or ctx.prev_output or {}
    criteria = input_data.get("criteria", "Check for accuracy, completeness, and safety")

    system_prompt = (
        "You are a strict peer reviewer for SOC agent outputs. Review the provided output against "
        "the criteria and return a JSON object with exactly these keys: approved (bool), reason (string), "
        "issues (list of strings)."
    )
    user_prompt = json.dumps({"criteria": criteria, "output": output}, default=str)

    provider = get_provider()
    result = await provider.analyze(system_prompt, user_prompt)
    if not result.get("success"):
        raise RuntimeError(result.get("error", "LLM review failed"))

    return {
        "approved": bool(result.get("approved", False)),
        "reason": result.get("reason", ""),
        "issues": result.get("issues", []),
        "output": output,
    }


async def lead(input_data: dict, ctx: HandlerContext) -> dict:
    """Decompose an objective into sub-tasks and create pending child tasks."""
    objective = input_data.get("objective")
    if not objective:
        raise ValueError("objective is required for lead handler")

    context = input_data.get("context") or ctx.prev_output or {}

    system_prompt = (
        "You are a SOC lead agent. Decompose the objective into sub-tasks for a team of security agents. "
        "Return a JSON object with exactly these keys: plan (list of objects, each with agent_type, "
        "input, and description)."
    )
    user_prompt = json.dumps({"objective": objective, "context": context}, default=str)

    provider = get_provider()
    result = await provider.analyze(system_prompt, user_prompt)
    if not result.get("success"):
        raise RuntimeError(result.get("error", "LLM planning failed"))

    plan = result.get("plan", [])
    if not isinstance(plan, list):
        plan = []

    # Persist child tasks as pending. They are not auto-executed in this run;
    # a future engine enhancement can recursively execute them.
    from shared.models.agent import AgentTask

    child_ids = []
    for item in plan:
        child_input = dict(item.get("input", {}))
        child_input["_description"] = item.get("description", "")
        child = AgentTask(
            run_id=ctx.run.id,
            parent_task_id=ctx.task.id,
            agent_type=item.get("agent_type", "unknown"),
            input_data=child_input,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        ctx.session.add(child)
        child_ids.append(str(child.id))

    await ctx.session.flush()

    return {
        "objective": objective,
        "plan": plan,
        "child_task_ids": child_ids,
    }
