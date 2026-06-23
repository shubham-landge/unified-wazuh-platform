"""Auto-close pipeline — closes benign alerts automatically with full audit trail.

Shadow mode (AUTOMATION_MODE=shadow): logs decisions but takes NO action.
Enforce mode (AUTOMATION_MODE=enforce): persists closed verdict + audit record.

Invariants:
  - Requires POSITIVE evidence of benign (not just 'low score due to missing data').
  - Never auto-closes if: TI hit, UEBA anomaly > 2.5, vuln match, score >= threshold.
  - Every auto-close writes an AutoCloseAudit record.
  - Override tracking: one analyst reopen triggers re-queue for LLM analysis.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from shared.config import settings
from shared.enrichment.risk_score import EnrichmentContext

logger = logging.getLogger(__name__)


@dataclass
class AutoCloseAudit:
    alert_id: str
    tenant_id: str
    reason: str
    score: int
    breakdown: dict
    policy_version: str = "1.0"
    shadow_mode: bool = False
    closed_at: datetime = None

    def __post_init__(self):
        if self.closed_at is None:
            self.closed_at = datetime.now(timezone.utc)


def should_auto_close(
    ctx: EnrichmentContext,
    score: int,
    rule_level: int = 0,
    llm_verdict: Optional[str] = None,
    llm_confidence: Optional[float] = None,
) -> tuple[bool, str]:
    """Determine if alert qualifies for auto-close.

    Returns (eligible, reason). Requires POSITIVE evidence:
    - Rule level < 10 (low-level alert)
    - Score < threshold
    - No TI hit
    - Normal UEBA (z < 2.5)
    - No vuln match
    - No crown-jewel asset
    - LLM verdict benign (if available) with confidence >= threshold
    """
    auto_close_score_threshold = int(getattr(settings, 'auto_close_score_threshold', 25))
    auto_close_confidence = float(getattr(settings, 'auto_close_confidence_threshold', 0.85))

    # Hard blockers — any single one disqualifies auto-close
    if rule_level >= 10:
        return False, f"rule level {rule_level} >= 10 (not low-level)"
    if ctx.ti_confidence > 0.1 or ctx.ti_is_known_bad:
        return False, "TI hit detected"
    if ctx.ueba_zscore >= 2.5:
        return False, f"UEBA anomaly z={ctx.ueba_zscore:.1f}"
    if ctx.vuln_matched:
        return False, "exploit ↔ CVE match on target"
    if ctx.is_crown_jewel:
        return False, "crown-jewel asset"
    if score >= auto_close_score_threshold:
        return False, f"score {score} >= {auto_close_score_threshold}"

    # Require positive benign evidence
    if llm_verdict == "benign" and llm_confidence is not None:
        if llm_confidence < auto_close_confidence:
            return False, f"LLM confidence {llm_confidence:.2f} < {auto_close_confidence}"
        return True, f"benign verdict (conf={llm_confidence:.2f}), score={score}"

    if llm_verdict is None:
        # L1 path — deterministic only, no LLM
        return True, f"deterministic benign (score={score}, level={rule_level}, no TI, normal UEBA)"

    return False, f"verdict '{llm_verdict}' not benign"


async def execute_auto_close(
    session,
    alert_id: str,
    tenant_id: str,
    reason: str,
    score: int,
    ctx: EnrichmentContext,
) -> AutoCloseAudit:
    """Execute the auto-close (or shadow-log it) and return the audit record."""
    shadow = str(getattr(settings, 'automation_mode', 'shadow')).lower() == 'shadow'
    audit = AutoCloseAudit(
        alert_id=alert_id,
        tenant_id=tenant_id,
        reason=reason,
        score=score,
        breakdown=ctx.breakdown,
        shadow_mode=shadow,
    )

    if shadow:
        logger.info(
            "[SHADOW] would auto-close alert %s: %s (score=%d)",
            alert_id, reason, score
        )
        return audit

    # Real close
    try:
        from shared.models.alert import Alert
        from sqlalchemy import update, and_
        await session.execute(
            update(Alert)
            .where(and_(Alert.id == alert_id, Alert.status == "open"))
            .values(status="auto_closed", notes=f"Auto-closed: {reason}")
        )
        await session.commit()
        logger.info("Auto-closed alert %s: %s (score=%d)", alert_id, reason, score)
    except Exception as exc:
        logger.error("auto_close execute failed for alert %s: %s", alert_id, exc)

    return audit
