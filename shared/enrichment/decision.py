"""Decision engine — maps risk scores to response levels L0-L4.

Default behaviour is shadow mode: logs the decision but never enforces.
Kill switches (global or per-tier) disable enforcement entirely.
"""

import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from shared.config import settings
from shared.models.alert import Alert
from shared.enrichment.pipeline import EnrichmentResult

logger = logging.getLogger(__name__)


class DecisionLevel(IntEnum):
    """Escalation / response levels."""

    L0_BENIGN = 0
    L1_LOW = 1
    L2_MEDIUM = 2
    L3_HIGH = 3
    L4_CRITICAL = 4


@dataclass
class Decision:
    level: DecisionLevel
    score: int
    breakdown: dict
    enforced: bool
    reason: str


# Score → level mapping.
_LEVEL_BANDS = [
    (81, DecisionLevel.L4_CRITICAL),
    (61, DecisionLevel.L3_HIGH),
    (41, DecisionLevel.L2_MEDIUM),
    (21, DecisionLevel.L1_LOW),
    (0, DecisionLevel.L0_BENIGN),
]


def _score_to_level(score: int) -> DecisionLevel:
    for threshold, level in _LEVEL_BANDS:
        if score >= threshold:
            return level
    return DecisionLevel.L0_BENIGN


def decide(
    score: int,
    alert: Alert,
    enrichment: EnrichmentResult,
    *,
    breakdown: dict | None = None,
) -> Decision:
    """Map a risk score to a decision level L0-L4.

    By default runs in shadow mode: logs the decision for observability but
    sets enforced=False so nothing is auto-escalated. Set
    ENRICHMENT_DECISION_SHADOW_MODE=false to enable enforcement.

    The global kill switch (ENRICHMENT_KILL_SWITCH=true) forces L0.

    Args:
        score: Risk score 0-100 from compute_risk_score.
        alert: The originating alert (used for logging context).
        enrichment: The EnrichmentResult from the pipeline.
        breakdown: Optional score breakdown dict.

    Returns:
        Decision with level, enforced flag, and reason.
    """
    level = _score_to_level(score)

    if settings.enrichment_kill_switch:
        return Decision(
            level=DecisionLevel.L0_BENIGN,
            score=score,
            breakdown=breakdown or {},
            enforced=False,
            reason="Global kill switch active",
        )

    shadow = settings.enrichment_decision_shadow_mode
    enforced = not shadow

    reason = f"Score={score} → L{int(level)}"
    if shadow:
        reason += " (shadow mode — logged, not enforced)"

    log_msg = (
        "Decision: alert=%s score=%d level=L%d enforced=%s reason=%s",
        str(alert.id),
        score,
        int(level),
        enforced,
        reason,
    )

    if level >= DecisionLevel.L3_HIGH:
        logger.warning(*log_msg)
    elif level >= DecisionLevel.L2_MEDIUM:
        logger.info(*log_msg)
    else:
        logger.debug(*log_msg)

    return Decision(
        level=level,
        score=score,
        breakdown=breakdown or {},
        enforced=enforced,
        reason=reason,
    )
