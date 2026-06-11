from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from starlette.status import HTTP_404_NOT_FOUND

from app.db import get_db
from shared.models.alert import Alert
from shared.models.ai_triage_result import AiTriageResult
from shared.models.case import Case
from app.middleware.auth import validate_api_key

router = APIRouter(prefix="/triage", tags=["triage"])


class TriageRequest(BaseModel):
    alert_id: str


@router.post("/run")
async def run_triage(
    body: TriageRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    from shared.config import settings

    import uuid
    try:
        alert_uid = uuid.UUID(body.alert_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid alert ID")

    query = select(Alert).where(Alert.id == alert_uid)
    result = await db.execute(query)
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Alert not found")

    triage_result = AiTriageResult(
        alert_id=alert_uid,
        model_name=settings.ollama_model,
        model_version="1.0",
        prompt_text=f"Analyze this Wazuh alert: {alert.rule_description}",
        response_text="Triage pending — LLM connector not yet configured.",
        summary=f"Alert: {alert.rule_description}",
        category="triage_pending",
        severity="medium",
        confidence=0.5,
        false_positive_likelihood=0.3,
        mitre_mapping=[
            {"tactic": alert.mitre_tactic, "technique": alert.mitre_technique}
        ] if alert.mitre_tactic else [],
        investigation_steps=[
            "Check alert details in Wazuh dashboard",
            "Review source IP and user",
            "Correlate with other alerts from same agent",
        ],
        do_not_do=[
            "Do not disable the agent without verification",
            "Do not block the source IP without confirmation",
        ],
        escalation_required=False,
        success=True,
    )
    db.add(triage_result)
    await db.flush()

    case = Case(
        alert_id=alert_uid,
        title=alert.rule_description or "Alert triage case",
        severity="medium",
        category="triage",
    )
    db.add(case)
    await db.commit()

    return {
        "status": "success",
        "triage_id": str(triage_result.id),
        "case_id": str(case.id),
        "summary": triage_result.summary,
        "severity": triage_result.severity,
        "confidence": float(triage_result.confidence),
        "false_positive_likelihood": float(triage_result.false_positive_likelihood),
        "escalation_required": triage_result.escalation_required,
    }
