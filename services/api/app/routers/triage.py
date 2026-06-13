import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel, Field
from starlette.status import HTTP_202_ACCEPTED, HTTP_404_NOT_FOUND, HTTP_503_SERVICE_UNAVAILABLE, HTTP_400_BAD_REQUEST

from app.db import get_db
from shared.models.alert import Alert
from shared.models.ai_triage_result import AiTriageResult
from shared.models.feedback import UserFeedback
from app.middleware.auth import validate_api_key
from app.middleware.auth_jwt import get_current_user
from shared.auth import TokenData
from shared.config import settings

router = APIRouter(prefix="/triage", tags=["triage"])


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

    from shared.connectors.llm_provider import get_provider
    from shared.config import settings

    provider = get_provider()

    # Load system prompt from file
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

    try:
        result_data = await provider.analyze(system_prompt=system_prompt, user_prompt=user_prompt)
    except Exception as e:
        raise HTTPException(status_code=HTTP_503_SERVICE_UNAVAILABLE, detail=f"LLM provider error: {e}")

    triage_result = AiTriageResult(
        alert_id=alert_uid,
        model_name=provider.name(),
        prompt_text=user_prompt,
        response_text=json.dumps(result_data),
        summary=result_data.get("summary", alert.rule_description),
        category=result_data.get("category", "unknown"),
        severity=result_data.get("severity", "medium"),
        confidence=result_data.get("confidence", 0.5),
        false_positive_likelihood=result_data.get("false_positive_likelihood", 0.3),
        mitre_mapping=result_data.get("mitre_mapping", []),
        investigation_steps=result_data.get(
            "recommended_investigation_steps",
            result_data.get("investigation_steps", []),
        ),
        do_not_do=result_data.get("do_not_do", []),
        escalation_required=result_data.get("escalation_required", False),
        suggested_soc_action=result_data.get("recommended_soc_action"),
        success=result_data.get("success", True),
        error_message=result_data.get("error"),
    )
    db.add(triage_result)
    await db.commit()

    return {
        "status": "accepted",
        "triage_id": str(triage_result.id),
        "alert_id": str(alert_uid),
        "summary": triage_result.summary,
        "severity": triage_result.severity,
        "confidence": float(triage_result.confidence),
        "false_positive_likelihood": float(triage_result.false_positive_likelihood),
        "escalation_required": triage_result.escalation_required,
        "model": provider.name(),
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
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="No triage result for this alert")

    return {
        "status": "success",
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
        except Exception:
            pass

    return {"status": "accepted", "feedback_id": str(feedback.id)}
