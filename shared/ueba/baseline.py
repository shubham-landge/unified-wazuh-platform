"""
Welford online algorithm for incremental mean/variance.
Each (entity_type, entity_value, metric) triplet has one UebaBaseline row.
Update it as new observations arrive; query it to detect anomalies.
"""
import math
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.ueba import UebaBaseline

logger = logging.getLogger(__name__)


async def update_baseline(
    session: AsyncSession,
    entity_type: str,
    entity_value: str,
    metric: str,
    observed: float,
    window_hours: int = 24,
) -> UebaBaseline:
    result = await session.execute(
        select(UebaBaseline).where(
            UebaBaseline.entity_type == entity_type,
            UebaBaseline.entity_value == entity_value,
            UebaBaseline.metric == metric,
        )
    )
    baseline = result.scalar_one_or_none()

    if baseline is None:
        baseline = UebaBaseline(
            entity_type=entity_type,
            entity_value=entity_value,
            metric=metric,
            window_hours=window_hours,
        )
        session.add(baseline)

    # Welford's online update
    baseline.n += 1
    delta = observed - baseline.mean
    baseline.mean += delta / baseline.n
    delta2 = observed - baseline.mean
    baseline.m2 += delta * delta2
    baseline.last_updated = datetime.now(timezone.utc)

    return baseline


def stddev(baseline: UebaBaseline) -> float:
    if baseline.n < 2:
        return 0.0
    return math.sqrt(baseline.m2 / (baseline.n - 1))


def z_score(baseline: UebaBaseline, observed: float) -> float:
    sd = stddev(baseline)
    if sd == 0:
        return 0.0
    return (observed - baseline.mean) / sd
