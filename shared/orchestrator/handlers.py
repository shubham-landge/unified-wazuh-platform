"""Agent handler implementations for the orchestration engine."""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import desc, select

from shared.config import settings
from shared.connectors.llm_provider import get_provider
from shared.models.agent import AgentDefinition
from shared.models.alert import Alert
from shared.models.alert_dedup import AlertIncident
from shared.models.ai_triage_result import AiTriageResult
from shared.models.approval import ApprovalRequest
from shared.models.case import Case
from shared.models.case_event import CaseEvent
from shared.models.soar import SoarExecution, SoarPlaybook
from shared.models.ueba import UebaAnomaly
from shared.orchestrator.engine import HandlerContext

logger = logging.getLogger(__name__)


async def _few_shot(agent_type: str, input_data: dict) -> list[dict]:
    """Retrieve few-shot examples from RAG skill memory (Antigravity zone).

    The file is not required to exist yet; if unavailable an empty list is
    returned so the handler degrades gracefully.
    """
    try:
        from shared.rag.few_shot import retrieve
        return await retrieve(agent_type, input_data)
    except Exception as exc:
        logger.debug("few_shot.retrieve unavailable for %s: %s", agent_type, exc)
        return []


async def _load_alert(session, alert_id: str | uuid.UUID) -> Alert | None:
    try:
        if isinstance(alert_id, str):
            alert_id = uuid.UUID(alert_id)
        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        return result.scalar_one_or_none()
    except Exception as exc:
        logger.warning("Failed to load alert %s: %s", alert_id, exc)
        return None


def _write_actions() -> set[str]:
    """Actions that mutate state and therefore require policy/approval gating."""
    return {"soar_run", "case_create", "notify"}


async def _check_existing_approval(
    session,
    tenant_id: uuid.UUID | None,
    action_type: str,
    target_ref: str | None,
) -> ApprovalRequest | None:
    """Return a non-expired approved request for the same action/target if one exists."""
    from sqlalchemy import and_
    result = await session.execute(
        select(ApprovalRequest)
        .where(
            and_(
                ApprovalRequest.tenant_id == tenant_id,
                ApprovalRequest.action_type == action_type,
                ApprovalRequest.target_ref == target_ref,
                ApprovalRequest.status == "approved",
                ApprovalRequest.expires_at > datetime.now(timezone.utc),
            )
        )
        .order_by(ApprovalRequest.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _load_definition(session, definition_id: uuid.UUID) -> AgentDefinition | None:
    result = await session.execute(
        select(AgentDefinition).where(AgentDefinition.id == definition_id)
    )
    return result.scalar_one_or_none()


def _risk_level_for(input_data: dict) -> str:
    """Infer a risk level from handler input for approval requests."""
    risk = input_data.get("risk_level") or input_data.get("severity") or "medium"
    if risk in ("critical", "high", "medium", "low"):
        return risk
    return "medium"


async def policy_guard(input_data: dict, ctx: HandlerContext) -> dict:
    """Approve or deny a proposed action based on agent autonomy level and policy.

    If the agent has "full" autonomy the action is approved. If it is "read-only"
    the action is denied. If it is "approval" (default), an ApprovalRequest is
    created and the action is held pending human review unless an existing valid
    approved request already exists for the same action/target.
    """
    action_type = input_data.get("action_type")
    action_params = input_data.get("action_params") or {}
    target_ref = input_data.get("target_ref") or action_params.get("alert_id") or action_params.get("case_id")
    rationale = input_data.get("rationale") or f"Agent requested {action_type}"

    if not action_type:
        raise ValueError("action_type is required for policy_guard handler")

    # Reuse an existing approved, non-expired request when present.
    existing = await _check_existing_approval(
        ctx.session, ctx.run.tenant_id, action_type, target_ref
    )
    if existing:
        return {
            "approved": True,
            "reason": "Existing approved request found",
            "approval_id": str(existing.id),
            "status": "approved",
        }

    definition = await _load_definition(ctx.session, ctx.run.definition_id)
    autonomy = "approval"
    agent_name = "unknown"
    if definition:
        autonomy = definition.autonomy_level or "approval"
        agent_name = definition.name or agent_name

    # Read-only agents never perform write actions.
    if autonomy == "read-only":
        return {
            "approved": False,
            "reason": "Agent is configured as read-only",
            "action_type": action_type,
            "target_ref": target_ref,
        }

    # Full-autonomy agents are allowed to proceed.
    if autonomy == "full":
        return {
            "approved": True,
            "reason": "Agent has full autonomy",
            "action_type": action_type,
            "target_ref": target_ref,
        }

    # Approval mode: create a pending ApprovalRequest.
    few_shot = await _few_shot("policy_guard", input_data)
    if few_shot:
        rationale = f"{rationale}\n\nFew-shot context:\n{json.dumps(few_shot, default=str)}"

    approval = ApprovalRequest(
        tenant_id=ctx.run.tenant_id,
        requested_by=f"agent:{agent_name}",
        action_type=action_type,
        action_params=action_params if isinstance(action_params, dict) else {},
        target_ref=target_ref,
        rationale=rationale,
        risk_level=_risk_level_for(input_data),
        status="pending",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=3600),
    )
    ctx.session.add(approval)
    await ctx.session.flush()

    return {
        "approved": False,
        "approval_id": str(approval.id),
        "status": "pending",
        "reason": "Action requires human approval",
        "action_type": action_type,
        "target_ref": target_ref,
    }


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
    guard = await policy_guard(
        {
            "action_type": "case_create",
            "action_params": input_data,
            "target_ref": alert_id,
            "rationale": input_data.get("rationale", f"Create case: {title}"),
            "risk_level": input_data.get("severity", "medium"),
        },
        ctx,
    )
    if not guard.get("approved"):
        return {
            "status": "blocked",
            "action": "case_create",
            "reason": guard.get("reason"),
            "approval_id": guard.get("approval_id"),
            "case_id": None,
        }

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
        "approved_by": guard.get("approval_id"),
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

    guard = await policy_guard(
        {
            "action_type": "soar_run",
            "action_params": input_data,
            "target_ref": alert_id or alert.get("id"),
            "rationale": input_data.get("rationale", "SOAR playbook execution"),
            "risk_level": input_data.get("severity", "medium"),
        },
        ctx,
    )
    if not guard.get("approved"):
        return {
            "status": "blocked",
            "action": "soar_run",
            "reason": guard.get("reason"),
            "approval_id": guard.get("approval_id"),
            "playbook_runs": [],
        }

    engine = SOAREngine(session=ctx.session)
    results = await engine.run_for_alert(alert)
    return {"playbook_runs": results, "approved_by": guard.get("approval_id")}


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


async def correlation(input_data: dict, ctx: HandlerContext) -> dict:
    """Group related alerts into one incident bundle.

    Looks for an existing open AlertIncident keyed by the strongest common
    attribute across the supplied alert IDs and either creates a new incident
    or appends to the existing one.
    """
    alert_ids = input_data.get("alert_ids") or [input_data.get("alert_id")]
    alert_ids = [a for a in alert_ids if a]
    if not alert_ids:
        raise ValueError("alert_ids or alert_id is required for correlation handler")

    alerts = []
    for raw_id in alert_ids:
        alert = await _load_alert(ctx.session, raw_id)
        if alert:
            alerts.append(alert)

    if not alerts:
        raise ValueError(f"No alerts found for ids {alert_ids}")

    # Prefer a common grouping attribute; fall back to a deterministic compound key.
    first = alerts[0]
    group_key_parts = []
    if first.source_ip:
        group_key_parts.append(f"src:{first.source_ip}")
    if first.user_name:
        group_key_parts.append(f"user:{first.user_name}")
    if first.mitre_technique:
        group_key_parts.append(f"technique:{first.mitre_technique}")
    if first.agent_id:
        group_key_parts.append(f"agent:{first.agent_id}")
    group_key = "|".join(group_key_parts) if group_key_parts else f"rule:{first.rule_id}"

    # Look for an existing open incident with the same grouping key.
    result = await ctx.session.execute(
        select(AlertIncident)
        .where(
            AlertIncident.group_key == group_key,
            AlertIncident.status == "open",
        )
        .order_by(AlertIncident.created_at.desc())
        .limit(1)
    )
    incident = result.scalar_one_or_none()

    if incident:
        incident.alert_count += len(alerts)
        incident.last_alert_at = datetime.now(timezone.utc)
        if first.severity in ("critical", "high"):
            incident.severity = first.severity
        await ctx.session.flush()
    else:
        incident = AlertIncident(
            tenant_id=ctx.run.tenant_id,
            group_key=group_key,
            rule_id=first.rule_id,
            rule_description=first.rule_description,
            agent_id=first.agent_id,
            source_ip=first.source_ip,
            alert_count=len(alerts),
            severity=first.severity,
            status="open",
            first_alert_at=datetime.now(timezone.utc),
            last_alert_at=datetime.now(timezone.utc),
            notes=input_data.get("notes"),
        )
        ctx.session.add(incident)
        await ctx.session.flush()

    few_shot = await _few_shot("correlation", input_data)

    return {
        "incident_id": str(incident.id),
        "group_key": group_key,
        "alert_count": incident.alert_count,
        "severity": incident.severity,
        "status": incident.status,
        "alert_ids": [str(a.id) for a in alerts],
        "few_shot_count": len(few_shot),
    }


async def response_planner(input_data: dict, ctx: HandlerContext) -> dict:
    """Draft a response playbook for an alert without executing it."""
    alert_id = input_data.get("alert_id")
    if not alert_id:
        raise ValueError("alert_id is required for response_planner handler")

    alert = await _load_alert(ctx.session, alert_id)
    if not alert:
        raise ValueError(f"Alert {alert_id} not found")

    triage_result = None
    try:
        triage_res = await ctx.session.execute(
            select(AiTriageResult)
            .where(AiTriageResult.alert_id == alert.id)
            .order_by(AiTriageResult.created_at.desc())
            .limit(1)
        )
        triage_result = triage_res.scalar_one_or_none()
    except Exception as exc:
        logger.warning("Failed to load triage for alert %s: %s", alert_id, exc)

    alert_dict = {
        "id": str(alert.id),
        "rule_description": alert.rule_description,
        "severity": alert.severity,
        "rule_level": alert.rule_level,
        "source_ip": alert.source_ip,
        "destination_ip": getattr(alert, "destination_ip", None),
        "user_name": alert.user_name,
        "agent_name": alert.agent_name,
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
    }
    triage_dict = {
        "summary": triage_result.summary if triage_result else None,
        "category": triage_result.category if triage_result else None,
        "severity": triage_result.severity if triage_result else None,
        "confidence": float(triage_result.confidence) if triage_result else None,
        "recommended_action": triage_result.suggested_soc_action if triage_result else None,
    }

    few_shot = await _few_shot("response_planner", input_data)

    system_prompt = (
        "You are a defensive SOC response planner. Draft a non-executed response playbook "
        "for the alert below. Return valid JSON with: steps (list of strings), investigation_plan "
        "(string), estimated_effort (string), required_tools (list of strings). "
        "Never recommend destructive actions."
    )
    user_prompt = json.dumps(
        {"alert": alert_dict, "triage": triage_dict, "few_shot": few_shot},
        default=str,
    )

    provider = get_provider()
    result = await provider.analyze(system_prompt, user_prompt)
    if not result.get("success"):
        raise RuntimeError(result.get("error", "Response planning failed"))

    steps = result.get("steps", [])
    if not isinstance(steps, list):
        steps = [str(steps)]

    playbook = SoarPlaybook(
        tenant_id=ctx.run.tenant_id,
        name=input_data.get("name") or f"Draft: {alert.rule_description or 'response'}",
        description=result.get("investigation_plan", ""),
        trigger_type="manual",
        steps=steps,
        enabled=False,
        created_by=f"agent:{ctx.task.agent_type}",
    )
    ctx.session.add(playbook)
    await ctx.session.flush()

    return {
        "playbook_id": str(playbook.id),
        "name": playbook.name,
        "steps": steps,
        "investigation_plan": result.get("investigation_plan", ""),
        "estimated_effort": result.get("estimated_effort", ""),
        "required_tools": result.get("required_tools", []),
        "draft": True,
    }


async def evidence_pack(input_data: dict, ctx: HandlerContext) -> dict:
    """Build a structured evidence bundle for a case or alert."""
    case_id = input_data.get("case_id")
    alert_id = input_data.get("alert_id")

    if not case_id and not alert_id:
        raise ValueError("case_id or alert_id is required for evidence_pack handler")

    case = None
    if case_id:
        try:
            case_uuid = uuid.UUID(str(case_id)) if isinstance(case_id, str) else case_id
            result = await ctx.session.execute(select(Case).where(Case.id == case_uuid))
            case = result.scalar_one_or_none()
        except Exception as exc:
            logger.warning("Failed to load case %s: %s", case_id, exc)

    alert = None
    if alert_id:
        alert = await _load_alert(ctx.session, alert_id)
    elif case and case.alert_id:
        alert = await _load_alert(ctx.session, case.alert_id)

    triage_result = None
    if alert:
        try:
            triage_res = await ctx.session.execute(
                select(AiTriageResult)
                .where(AiTriageResult.alert_id == alert.id)
                .order_by(AiTriageResult.created_at.desc())
                .limit(1)
            )
            triage_result = triage_res.scalar_one_or_none()
        except Exception as exc:
            logger.warning("Failed to load triage for evidence pack: %s", exc)

    timeline = []
    actions = []
    if case:
        try:
            events_res = await ctx.session.execute(
                select(CaseEvent).where(CaseEvent.case_id == case.id).order_by(CaseEvent.created_at)
            )
            timeline = [
                {
                    "event_type": e.event_type,
                    "description": e.description,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                    "meta": e.event_meta,
                }
                for e in events_res.scalars().all()
            ]
        except Exception as exc:
            logger.warning("Failed to load case events: %s", exc)

        try:
            exec_res = await ctx.session.execute(
                select(SoarExecution).where(SoarExecution.alert_id == case.alert_id)
            )
            actions = [
                {
                    "action_type": "soar_execution",
                    "status": e.status,
                    "result": e.result,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in exec_res.scalars().all()
            ]
        except Exception as exc:
            logger.warning("Failed to load soar executions: %s", exc)

    enrichment = input_data.get("enrichment") or []

    pack = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": {
            "id": str(case.id) if case else None,
            "title": case.title if case else None,
            "severity": case.severity if case else None,
            "status": case.status if case else None,
        },
        "alert": {
            "id": str(alert.id) if alert else None,
            "rule_description": alert.rule_description if alert else None,
            "severity": alert.severity if alert else None,
            "source_ip": alert.source_ip if alert else None,
            "user_name": alert.user_name if alert else None,
            "agent_name": alert.agent_name if alert else None,
        },
        "triage": {
            "summary": triage_result.summary if triage_result else None,
            "category": triage_result.category if triage_result else None,
            "severity": triage_result.severity if triage_result else None,
            "confidence": float(triage_result.confidence) if triage_result else None,
            "mitre_mapping": triage_result.mitre_mapping if triage_result else None,
        },
        "enrichment": enrichment,
        "timeline": timeline,
        "actions": actions,
    }

    return {"evidence_pack": pack, "target_type": "case" if case else "alert"}
