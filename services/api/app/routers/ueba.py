import uuid
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from shared.models.ueba import UebaBaseline, UebaAnomaly

router = APIRouter(prefix="/ueba", tags=["ueba"])


class BaselineCreate(BaseModel):
    subject_type: str
    subject_id: str
    metric_name: str
    baseline_value: float | None = None
    stddev: float | None = None
    window_days: int = 30


class AnomalyCreate(BaseModel):
    baseline_id: uuid.UUID | None = None
    subject_type: str
    subject_id: str
    anomaly_type: str
    score: float | None = None
    severity: str | None = None
    description: str | None = None
    features: dict = Field(default_factory=dict)


def _row(item):
    data = {}
    for key, value in item.__dict__.items():
        if key.startswith("_"):
            continue
        if hasattr(value, "isoformat"):
            value = value.isoformat()
        elif isinstance(value, uuid.UUID):
            value = str(value)
        data[key] = value
    return data


@router.get("/baselines")
async def list_baselines(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    rows = (
        await db.execute(select(UebaBaseline).order_by(desc(UebaBaseline.created_at)).limit(limit))
    ).scalars().all()
    return {"status": "success", "count": len(rows), "baselines": [_row(row) for row in rows]}


@router.post("/baselines", status_code=201)
async def create_baseline(
    body: BaselineCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    baseline = UebaBaseline(
        **body.model_dump(),
        tenant_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
    )
    db.add(baseline)
    await db.commit()
    await db.refresh(baseline)
    return {"status": "success", "baseline": _row(baseline)}


@router.get("/anomalies")
async def list_anomalies(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    rows = (
        await db.execute(select(UebaAnomaly).order_by(desc(UebaAnomaly.created_at)).limit(limit))
    ).scalars().all()
    return {"status": "success", "count": len(rows), "anomalies": [_row(row) for row in rows]}


@router.post("/anomalies", status_code=201)
async def create_anomaly(
    body: AnomalyCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    anomaly = UebaAnomaly(
        **body.model_dump(),
        tenant_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
    )
    db.add(anomaly)
    await db.commit()
    await db.refresh(anomaly)
    return {"status": "success", "anomaly": _row(anomaly)}
