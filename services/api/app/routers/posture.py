import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from shared.models.alert import Alert
from shared.models.case import Case
from shared.models.ueba import UebaAnomaly
from shared.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/posture", tags=["posture"])


class PostureScore(BaseModel):
    tenant_id: str | None
    score: int
    max_score: int
    components: dict
    generated_at: str


def _clamp(value: int, min_value: int = 0, max_value: int = 100) -> int:
    return max(min_value, min(max_value, value))


@router.get("/score", response_model=PostureScore)
async def posture_score(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    tenant_uuid = None
    if tenant_id:
        import uuid

        tenant_uuid = uuid.UUID(tenant_id)

    filters = {}
    if tenant_uuid:
        filters["tenant_id"] = tenant_uuid

    # Open cases penalty (max -30)
    open_cases_query = select(func.count(Case.id)).where(Case.status != "closed")
    if tenant_uuid:
        open_cases_query = open_cases_query.where(Case.tenant_id == tenant_uuid)
    open_cases = (await db.execute(open_cases_query)).scalar() or 0
    open_cases_penalty = min(30, open_cases * 5)

    # Critical/high vulnerabilities penalty (max -30)
    vuln_query = select(func.count(Vulnerability.id)).where(
        Vulnerability.severity.in_(["critical", "high"]),
        Vulnerability.status.notin_(["patched", "verified", "false_positive"]),
    )
    if tenant_uuid:
        vuln_query = vuln_query.where(Vulnerability.tenant_id == tenant_uuid)
    vuln_count = (await db.execute(vuln_query)).scalar() or 0
    vuln_penalty = min(30, vuln_count * 5)

    # UEBA anomalies penalty (max -20)
    ueba_query = select(func.count(UebaAnomaly.id)).where(
        UebaAnomaly.severity.in_(["critical", "high"])
    )
    if tenant_uuid:
        ueba_query = ueba_query.where(UebaAnomaly.tenant_id == tenant_uuid)
    ueba_count = (await db.execute(ueba_query)).scalar() or 0
    ueba_penalty = min(20, ueba_count * 5)

    # Recent alert volume penalty (max -20)
    alert_query = select(func.count(Alert.id)).where(Alert.created_at >= day_ago)
    if tenant_uuid:
        alert_query = alert_query.where(Alert.tenant_id == tenant_uuid)
    alert_count = (await db.execute(alert_query)).scalar() or 0
    alert_penalty = min(20, alert_count // 10)

    score = _clamp(100 - open_cases_penalty - vuln_penalty - ueba_penalty - alert_penalty)

    return PostureScore(
        tenant_id=tenant_id,
        score=score,
        max_score=100,
        components={
            "open_cases": {"count": open_cases, "penalty": open_cases_penalty},
            "critical_high_vulnerabilities": {"count": vuln_count, "penalty": vuln_penalty},
            "ueba_anomalies": {"count": ueba_count, "penalty": ueba_penalty},
            "alerts_24h": {"count": alert_count, "penalty": alert_penalty},
        },
        generated_at=now.isoformat(),
    )
