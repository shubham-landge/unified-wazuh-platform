"""Rule-level historical accuracy from analyst feedback.

Computes how often the AI triage verdict was correct for alerts of a given
rule_id by joining AiTriageResult ⟶ UserFeedback.  The accuracy is the
fraction of feedback entries whose rating is >= 4 (analyst agreed).

Caching
-------
Results are Redis-cached under key ``rule_acc:{rule_id}`` for 1 hour so
repeated calls inside a scoring loop are cheap.

Async session
-------------
The function accepts an AsyncSession.  When called without a session it
falls back to a synchronous helper (mirroring the existing legacy pattern
for backward compatibility).
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.ai_triage_result import AiTriageResult
from shared.models.feedback import UserFeedback
from shared.models.alert import Alert

logger = logging.getLogger(__name__)

MIN_SAMPLES = 5
CACHE_TTL_SECONDS = 3600


async def rule_historical_accuracy(
    rule_id: int | None,
    session: AsyncSession | None = None,
) -> float | None:
    """Return the fraction of analyst-agreed verdicts for *rule_id*.

    Joins ``UserFeedback`` → ``AiTriageResult`` → ``Alert`` to isolate
    feedback for a specific correlation rule.  An individual feedback is
    counted as *correct* when its **rating ≥ 4**.

    Parameters
    ----------
    rule_id:
        The rule to query.  ``None`` returns ``None`` immediately.
    session:
        An open async database session.  If ``None`` the function falls
        back to a synchronous Redis→DB path (backward compat).

    Returns
    -------
    float | None
        Accuracy ∈ [0.0, 1.0] or ``None`` when < *MIN_SAMPLES* (5)
        feedback entries exist for this rule.
    """
    if rule_id is None:
        return None

    # ── Redis cache check ──────────────────────────────────────────────
    cached = await _redis_get(rule_id)
    if cached is not None:
        return cached

    # ── Primary path: async ORM ────────────────────────────────────────
    if session is not None:
        try:
            total, correct = await _compute_from_orm(session, rule_id)
            if total < MIN_SAMPLES:
                return None
            acc = correct / total
            await _redis_set(rule_id, acc)
            return acc
        except Exception as exc:
            logger.debug("rule_historical_accuracy ORM error: %s", exc)
            return None

    # ── Fallback: sync engine (legacy compat) ──────────────────────────
    return await _compute_sync_fallback(rule_id)


# ═══════════════════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════════════════


async def _compute_from_orm(
    session: AsyncSession,
    rule_id: int,
) -> tuple[int, int]:
    """Run the accuracy query using the SQLAlchemy async ORM.

    Uses a scalar subquery to collect AiTriageResult IDs linked to
    alerts with *rule_id*, then counts total and correct (rating >= 4)
    UserFeedback rows against that pool in two simple queries.
    """

    # Scalar subquery: triage result IDs for alerts with this rule_id.
    # Inner join is correct — we only want triage results that actually
    # link to an alert (alert_id is nullable but a NULL link cannot
    # contribute to a rule's accuracy).
    relevant_ids = (
        select(AiTriageResult.id)
        .join(Alert, AiTriageResult.alert_id == Alert.id)
        .where(Alert.rule_id == rule_id)
        .scalar_subquery()
    )

    # Count total feedback entries for these triage results.
    total_res = await session.execute(
        select(func.count(UserFeedback.id)).where(
            UserFeedback.triage_result_id.in_(relevant_ids)
        )
    )
    total: int = total_res.scalar() or 0

    if total < MIN_SAMPLES:
        return total, 0

    # Count correct feedback entries (rating >= 4).
    correct_res = await session.execute(
        select(func.count(UserFeedback.id)).where(
            UserFeedback.triage_result_id.in_(relevant_ids),
            UserFeedback.rating >= 4,
        )
    )
    correct: int = correct_res.scalar() or 0

    return total, correct


# ── Redis helpers ──────────────────────────────────────────────────────


async def _redis_get(rule_id: int) -> float | None:
    try:
        from shared.config import settings
        import redis.asyncio as _aredis
        r = _aredis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=1,
        )
        raw = await r.get(f"rule_acc:{rule_id}")
        await r.aclose()
        if raw is not None:
            return float(raw)
    except Exception:
        pass
    return None


async def _redis_set(rule_id: int, value: float) -> None:
    try:
        from shared.config import settings
        import redis.asyncio as _aredis
        r = _aredis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=1,
        )
        await r.setex(f"rule_acc:{rule_id}", CACHE_TTL_SECONDS, str(value))
        await r.aclose()
    except Exception:
        pass


# ── Sync fallback (legacy compat) ─────────────────────────────────────


async def _compute_sync_fallback(rule_id: int) -> float | None:
    """Execute the accuracy query against a synchronous engine.

    Used when no async session is provided so the function still works
    from synchronous call-sites like the tiered router.
    """
    from shared.config import settings
    from sqlalchemy import create_engine, text

    try:
        engine = create_engine(
            settings.database_sync_url,
            pool_size=1,
            max_overflow=0,
        )
        with engine.connect() as conn:
            result = conn.execute(
                text(
                    """
                    SELECT
                        COUNT(*) AS total,
                        SUM(CASE WHEN uf.rating >= 4 THEN 1 ELSE 0 END) AS correct
                    FROM user_feedback uf
                    JOIN ai_triage_results atr ON uf.triage_result_id = atr.id
                    JOIN alerts a ON atr.alert_id = a.id
                    WHERE a.rule_id = :rule_id
                    """
                ),
                {"rule_id": str(rule_id)},
            )
            row = result.fetchone()
            if row is None:
                return None
            total = int(getattr(row, "total", 0) or 0)
            if total < MIN_SAMPLES:
                return None
            correct = int(getattr(row, "correct", 0) or 0)
            acc = correct / total
            await _redis_set(rule_id, acc)
            return acc
    except Exception as exc:
        logger.debug("rule_historical_accuracy sync DB error: %s", exc)
    return None
