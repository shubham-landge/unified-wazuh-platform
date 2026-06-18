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

from app.db import get_db
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


_TRIAGE_PENDING_TIMEOUT_SECONDS = 600


async def _enqueue_triage(alert_id: str, triage_id: str, force_fast: bool) -> None:
    """Hand the triage to the TriageWorker via Redis instead of running the LLM
    in the API process. Survives API restarts and serializes inference on the
    worker, which also applies noise-gating, UEBA, SOAR, and case creation."""
    import redis.asyncio as redis

    r = redis.from_url(settings.redis_url, decode_responses=True)
    try:
        await r.lpush(
            "triage_queue",
            json.dumps({
                "alert_id": alert_id,
                "triage_id": triage_id,
                "manual": True,
                "force_fast": force_fast,
            }),
        )
    finally:
        await r.aclose()



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

    # Manual "Analyze" is interactive — default to the fast tier so the analyst
    # gets an answer quickly (configurable via TRIAGE_MANUAL_FORCE_FAST).
    force_fast = getattr(settings, "triage_manual_force_fast", True)
    await _enqueue_triage(str(alert_uid), str(triage_result.id), force_fast)

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
