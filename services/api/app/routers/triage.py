import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel, Field
from starlette.status import HTTP_202_ACCEPTED, HTTP_404_NOT_FOUND, HTTP_503_SERVICE_UNAVAILABLE, HTTP_400_BAD_REQUEST, HTTP_429_TOO_MANY_REQUESTS

from app.db import get_db, async_session as _async_session_factory
from shared.models.alert import Alert
from shared.models.ai_triage_result import AiTriageResult
from shared.models.feedback import UserFeedback
from app.middleware.auth import validate_api_key
from app.middleware.auth_jwt import get_current_user
from shared.auth import TokenData
from shared.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/triage", tags=["triage"])

_feedback_rate_limit = defaultdict(list)


class TriageRequest(BaseModel):
    alert_id: str


class FeedbackRequest(BaseModel):
    rating: int = Field(ge=1, le=5)
    category_correct: bool | None = None
    severity_correct: bool | None = None
    correction_text: str | None = None
    corrected_category: str | None = None
    corrected_severity: str | None = None
    corrected_confidence: float | None = Field(None, ge=0, le=1)


import asyncio

_triage_background_tasks = set()

# A pending triage older than this is considered dead (the background task was
# lost to a restart/OOM) and is reaped to a failed state so the UI stops polling.
_TRIAGE_PENDING_TIMEOUT_SECONDS = 600


async def _run_triage_in_background(
    alert_uid: uuid.UUID,
    triage_uid: uuid.UUID,
):
    try:
        async with _async_session_factory() as bg_db:
            result = await bg_db.execute(select(Alert).where(Alert.id == alert_uid))
            alert = result.scalar_one_or_none()
            if not alert:
                return

            from shared.connectors.llm_router import TieredRouter

            provider = await TieredRouter().get_provider(
                alert=alert, tenant_id=str(alert.tenant_id), db_session=bg_db
            )

            from pathlib import Path
            prompts_dir = Path(__file__).parent.parent / "prompts"
            system_prompt_path = prompts_dir / "system_soc_triage.md"
            try:
                raw = system_prompt_path.read_text()
                system_prompt = "\n".join(l for l in raw.splitlines() if not l.startswith("#")).strip()
            except FileNotFoundError:
                system_prompt = (
                    "You are a defensive SOC triage copilot for Wazuh. "
                    "Analyze the alert and return structured JSON only. "
                    "Never recommend destructive actions."
                )

            alert_prompt_path = prompts_dir / "alert_triage.md"
            try:
                template = alert_prompt_path.read_text()
                user_prompt = template.format(
                    rule_description=alert.rule_description or "",
                    rule_id=alert.rule_id or "",
                    rule_level=alert.rule_level or "",
                    rule_groups=", ".join(alert.rule_groups or []),
                    agent_name=alert.agent_name or "",
                    agent_ip=alert.agent_ip or "",
                    source_ip=alert.source_ip or "",
                    destination_ip=alert.destination_ip or "",
                    user_name=alert.user_name or "",
                    process_name=alert.process_name or "",
                    file_name=alert.file_name or "",
                    file_hash=alert.file_hash or "",
                    event_id=alert.event_id or "",
                    mitre_tactic=alert.mitre_tactic or "",
                    mitre_technique=alert.mitre_technique or "",
                    alert_timestamp=alert.alert_timestamp.isoformat() if alert.alert_timestamp else "",
                )
            except (FileNotFoundError, KeyError):
                user_prompt = (
                    f"Alert Rule: {alert.rule_description}\n"
                    f"Rule ID: {alert.rule_id} | Level: {alert.rule_level}\n"
                    f"Agent: {alert.agent_name} ({alert.agent_ip})\n"
                    f"Source IP: {alert.source_ip} | User: {alert.user_name}\n"
                    f"MITRE: {alert.mitre_tactic} / {alert.mitre_technique}\n"
                )

            # Enrich prompt with correlation context
            try:
                lookback = datetime.now(timezone.utc) - timedelta(hours=24)
                related_count = 0
                related_same_rule = 0
                alert_frequency = "first"
                if alert.source_ip:
                    count_result = await bg_db.execute(
                        select(func.count(Alert.id))
                        .where(
                            Alert.source_ip == alert.source_ip,
                            Alert.alert_timestamp >= lookback,
                            Alert.id != alert.id,
                        )
                    )
                    related_count = count_result.scalar() or 0
                    if alert.rule_id:
                        rule_result = await bg_db.execute(
                            select(func.count(Alert.id))
                            .where(
                                Alert.source_ip == alert.source_ip,
                                Alert.rule_id == alert.rule_id,
                                Alert.alert_timestamp >= lookback,
                                Alert.id != alert.id,
                            )
                        )
                        related_same_rule = rule_result.scalar() or 0
                    if related_count > 20:
                        alert_frequency = "very_frequent"
                    elif related_count > 5:
                        alert_frequency = "frequent"
                    elif related_count > 0:
                        alert_frequency = "repeated"

                enrichment_lines = []
                if related_count > 0:
                    enrichment_lines.append(f"\n## Correlation Context\n- Related alerts from same source IP (24h): {related_count}")
                    enrichment_lines.append(f"- Same rule ID from same IP (24h): {related_same_rule}")
                    enrichment_lines.append(f"- Alert frequency pattern: {alert_frequency}")
                if alert.mitre_tactic or alert.mitre_technique:
                    enrichment_lines.append(f"\n## MITRE ATT&CK\n- Tactic: {alert.mitre_tactic or 'N/A'}")
                    enrichment_lines.append(f"- Technique: {alert.mitre_technique or 'N/A'}")
                if alert.agent_name:
                    enrichment_lines.append(f"\n## Asset Context\n- Agent: {alert.agent_name} ({alert.agent_ip or 'N/A'})")
                    enrichment_lines.append(f"- Agent ID: {alert.agent_id or 'Unknown'}")
                if enrichment_lines:
                    user_prompt = user_prompt.rstrip() + "\n" + "\n".join(enrichment_lines)
            except Exception as e:
                logger.debug("Failed to enrich triage prompt: %s", e)

            try:
                result_data = await provider.analyze(system_prompt=system_prompt, user_prompt=user_prompt)
            except Exception as e:
                result_data = {"success": False, "error": str(e)}

            triage_result = await bg_db.get(AiTriageResult, triage_uid)
            if not triage_result:
                return

            if result_data.get("success", True) is False:
                triage_result.status = "failed"
                triage_result.error_message = result_data.get("error", "LLM analysis failed")
                triage_result.response_text = json.dumps(result_data)
                triage_result.success = False
                await bg_db.commit()
                return

            triage_result.status = "completed"
            triage_result.model_name = provider.name()
            triage_result.prompt_text = user_prompt
            triage_result.response_text = json.dumps(result_data)
            triage_result.summary = result_data.get("summary", alert.rule_description)
            triage_result.category = result_data.get("category", "unknown")
            triage_result.severity = result_data.get("severity", "medium")
            triage_result.confidence = result_data.get("confidence", 0.5)
            triage_result.false_positive_likelihood = result_data.get("false_positive_likelihood", 0.3)
            triage_result.mitre_mapping = result_data.get("mitre_mapping", [])
            triage_result.investigation_steps = result_data.get(
                "recommended_investigation_steps",
                result_data.get("investigation_steps", []),
            )
            triage_result.do_not_do = result_data.get("do_not_do", [])
            triage_result.escalation_required = result_data.get("escalation_required", False)
            triage_result.suggested_soc_action = result_data.get("recommended_soc_action")
            triage_result.success = result_data.get("success", True)
            triage_result.error_message = result_data.get("error")

            from shared.models.model_run import ModelRun
            from hashlib import sha256
            model_run = ModelRun(
                tenant_id=alert.tenant_id,
                model_name=provider.name(),
                prompt_hash=sha256(user_prompt.encode()).hexdigest()[:16],
                input_tokens=result_data.get("tokens_input"),
                output_tokens=result_data.get("tokens_output"),
                latency_ms=result_data.get("latency_ms"),
                success=result_data.get("success", True),
            )
            bg_db.add(model_run)
            await bg_db.commit()

    except Exception as e:
        logger.exception("Background triage failed for alert %s: %s", alert_uid, e)
        try:
            async with _async_session_factory() as err_db:
                triage_result = await err_db.get(AiTriageResult, triage_uid)
                if triage_result:
                    triage_result.status = "failed"
                    triage_result.error_message = str(e)
                    triage_result.success = False
                    await err_db.commit()
        except Exception:
            logger.exception("Failed to mark triage as failed for %s", triage_uid)


@router.post("/run", status_code=HTTP_202_ACCEPTED)
async def run_triage(
    body: TriageRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    try:
        alert_uid = uuid.UUID(body.alert_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid alert ID")

    result = await db.execute(select(Alert).where(Alert.id == alert_uid))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Alert not found")

    triage_result = AiTriageResult(
        alert_id=alert_uid,
        status="pending",
        model_name="",
        tenant_id=alert.tenant_id,
    )
    db.add(triage_result)
    await db.commit()
    await db.refresh(triage_result)

    task = asyncio.create_task(
        _run_triage_in_background(alert_uid, triage_result.id)
    )
    _triage_background_tasks.add(task)
    task.add_done_callback(_triage_background_tasks.discard)

    return {
        "status": "pending",
        "triage_id": str(triage_result.id),
        "alert_id": str(alert_uid),
    }


@router.get("/{alert_id}")
async def get_triage_result(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    try:
        alert_uid = uuid.UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid alert ID")

    result = await db.execute(
        select(AiTriageResult)
        .where(AiTriageResult.alert_id == alert_uid)
        .order_by(AiTriageResult.created_at.desc())
        .limit(1)
    )
    triage = result.scalar_one_or_none()
    if not triage:
        return {"status": "not_found", "triage_id": None}

    if triage.status == "pending":
        # Reaper: a background task that died (API restart, OOM-kill) would leave
        # this row "pending" forever and the dashboard would poll every 5s with no
        # end. Once it's older than the LLM timeout budget, fail it so the UI stops.
        created = triage.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - created).total_seconds()
        if age > _TRIAGE_PENDING_TIMEOUT_SECONDS:
            triage.status = "failed"
            triage.success = False
            triage.error_message = "Triage timed out (no result within budget)"
            await db.commit()
            return {
                "status": "failed",
                "triage_id": str(triage.id),
                "alert_id": str(triage.alert_id),
                "error": triage.error_message,
            }
        return {
            "status": "pending",
            "triage_id": str(triage.id),
            "alert_id": str(triage.alert_id),
        }

    return {
        "status": "completed",
        "triage_id": str(triage.id),
        "alert_id": str(triage.alert_id),
        "model": triage.model_name,
        "summary": triage.summary,
        "category": triage.category,
        "severity": triage.severity,
        "confidence": float(triage.confidence),
        "false_positive_likelihood": float(triage.false_positive_likelihood),
        "mitre_mapping": triage.mitre_mapping,
        "investigation_steps": triage.investigation_steps,
        "do_not_do": triage.do_not_do,
        "escalation_required": triage.escalation_required,
        "suggested_soc_action": triage.suggested_soc_action,
        "success": triage.success,
        "feedback_count": triage.feedback_count,
        "avg_rating": float(triage.avg_rating) if triage.avg_rating else None,
        "created_at": triage.created_at.isoformat() if triage.created_at else None,
    }


@router.post("/{triage_id}/feedback")
async def submit_feedback(
    triage_id: str,
    body: FeedbackRequest,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    user_id = current_user.user_id

    _feedback_rate_limit[user_id] = [t for t in _feedback_rate_limit.get(user_id, []) if t > now - timedelta(minutes=1)]
    if len(_feedback_rate_limit[user_id]) >= 10:
        raise HTTPException(status_code=HTTP_429_TOO_MANY_REQUESTS, detail="Too many feedback submissions. Please wait.")
    _feedback_rate_limit[user_id].append(now)

    try:
        triage_uid = uuid.UUID(triage_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid triage ID")

    result = await db.execute(select(AiTriageResult).where(AiTriageResult.id == triage_uid))
    triage = result.scalar_one_or_none()
    if not triage:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Triage result not found")

    feedback = UserFeedback(
        triage_result_id=triage_uid,
        tenant_id=current_user.tenant_id,
        rating=body.rating,
        category_correct=body.category_correct,
        severity_correct=body.severity_correct,
        correction_text=body.correction_text,
        corrected_category=body.corrected_category,
        corrected_severity=body.corrected_severity,
        corrected_confidence=body.corrected_confidence,
        reviewed_by=current_user.user_id,
    )
    db.add(feedback)

    triage.feedback_count = (triage.feedback_count or 0) + 1
    avg_result = await db.execute(
        select(func.avg(UserFeedback.rating)).where(UserFeedback.triage_result_id == triage_uid)
    )
    avg_val = avg_result.scalar()
    triage.avg_rating = round(float(avg_val), 2) if avg_val else body.rating

    await db.commit()

    if settings.feedback_enabled:
        try:
            import redis.asyncio as redis_async
            r = await redis_async.from_url(settings.redis_url, decode_responses=True)
            await r.lpush("feedback_queue", json.dumps({
                "feedback_id": str(feedback.id),
                "triage_result_id": triage_id,
                "rating": body.rating,
            }))
            await r.aclose()
        except Exception as e:
            logger.warning("Failed to enqueue feedback for triage %s: %s", triage_id, e)

    return {"status": "accepted", "feedback_id": str(feedback.id)}
