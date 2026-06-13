import math
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.ueba import UebaBaseline

logger = logging.getLogger(__name__)


async def update_baseline(
    session: AsyncSession,
    subject_type: str,
    subject_id: str,
    metric_name: str,
    observed: float,
    window_days: int = 30,
) -> UebaBaseline:
    result = await session.execute(
        select(UebaBaseline).where(
            UebaBaseline.subject_type == subject_type,
            UebaBaseline.subject_id == subject_id,
            UebaBaseline.metric_name == metric_name,
        )
    )
    baseline = result.scalar_one_or_none()

    if baseline is None:
        baseline = UebaBaseline(
            subject_type=subject_type,
            subject_id=subject_id,
            metric_name=metric_name,
            window_days=window_days,
        )
        session.add(baseline)

    baseline.n = (baseline.n or 0) + 1
    if baseline.mean is None:
        baseline.mean = 0.0
    if baseline.m2 is None:
        baseline.m2 = 0.0
    delta = observed - baseline.mean
    baseline.mean += delta / baseline.n
    delta2 = observed - baseline.mean
    baseline.m2 += delta * delta2
    baseline.baseline_value = baseline.mean
    baseline.stddev = _stddev(baseline)
    baseline.last_updated = datetime.now(timezone.utc)

    return baseline


def _stddev(baseline: UebaBaseline) -> float:
    if baseline.n < 2:
        return 0.0
    return math.sqrt(baseline.m2 / (baseline.n - 1))


def compute_z_score(baseline: UebaBaseline, observed: float) -> float:
    sd = _stddev(baseline)
    if sd == 0:
        return 0.0
    return (observed - baseline.mean) / sd