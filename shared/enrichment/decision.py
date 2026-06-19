"""L0–L4 decision gate — routes alerts without touching the LLM when possible.

    L0  suppress  — allowlist or score < L0_THRESHOLD and low level and no TI
    L1  auto_close — benign, low score, normal UEBA, no TI
    L2  triage     — ambiguous middle band → full LLM triage
    L3  escalate   — high score or high-confidence malicious TI on critical asset
    L4  critical   — extreme score or cross-domain advancing incident

All thresholds are tunable via config / env vars.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from shared.config import settings
from shared.enrichment.risk_score import EnrichmentContext

logger = logging.getLogger(__name__)


class DecisionLevel(str, Enum):
    L0_SUPPRESS = "suppress"
    L1_AUTO_CLOSE = "auto_close"
    L2_TRIAGE = "triage"
    L3_ESCALATE = "escalate"
    L4_CRITICAL = "critical"


@dataclass
class Decision:
    level: DecisionLevel
    score: int
    reason: str
    skip_llm: bool
    fast_llm_only: bool  # only narrative, verdict already determined
    auto_verdict: Optional[str] = None  # 'benign' | 'malicious' | None
    auto_severity: Optional[str] = None


def decide(ctx: EnrichmentContext, score: int, alert_level: int) -> Decision:
    """Apply the L0–L4 gate and return a Decision.

    Args:
        ctx:   populated EnrichmentContext (breakdown already computed)
        score: integer 0-100 from risk_score.compute()
        alert_level: raw Wazuh rule level (0-15)

    Returns:
        Decision with routing instructions.
    """
    l0 = int(getattr(settings, "risk_gate_l0_threshold", 15))
    l1 = int(getattr(settings, "risk_gate_l1_threshold", 25))
    l2_hi = int(getattr(settings, "risk_gate_l2_upper_threshold", 60))
    l3_hi = int(getattr(settings, "risk_gate_l3_threshold", 85))

    # L0 — suppress (no record, no LLM)
    if ctx.is_allowlisted:
        return Decision(
            level=DecisionLevel.L0_SUPPRESS,
            score=0,
            reason="allowlist match",
            skip_llm=True,
            fast_llm_only=False,
            auto_verdict="benign",
        )
    if score < l0 and alert_level < 7 and ctx.ti_confidence == 0:
        return Decision(
            level=DecisionLevel.L0_SUPPRESS,
            score=score,
            reason=f"score {score} < {l0} threshold, low level, no TI",
            skip_llm=True,
            fast_llm_only=False,
            auto_verdict="benign",
        )

    # L1 — auto-close (store record, no LLM)
    if (
        score < l1
        and ctx.ti_confidence == 0
        and not ctx.ti_is_known_bad
        and ctx.ueba_zscore < 2.5
        and not ctx.vuln_matched
        and alert_level < 10
    ):
        return Decision(
            level=DecisionLevel.L1_AUTO_CLOSE,
            score=score,
            reason=f"score {score} < {l1}, no TI hit, normal UEBA, low level",
            skip_llm=True,
            fast_llm_only=False,
            auto_verdict="benign",
            auto_severity="low",
        )

    # L4 — critical (high score OR cross-domain advancing incident)
    if score >= l3_hi or (ctx.ti_is_known_bad and ctx.is_crown_jewel):
        return Decision(
            level=DecisionLevel.L4_CRITICAL,
            score=score,
            reason=f"score {score} >= {l3_hi} or known-bad on crown-jewel",
            skip_llm=False,
            fast_llm_only=True,   # only narrative; verdict = malicious
            auto_verdict="malicious",
            auto_severity="critical",
        )

    # L3 — escalate (deterministic verdict, fast-tier LLM for narrative)
    if score >= l2_hi or (ctx.ti_confidence >= 0.8 and ctx.asset_criticality >= 7):
        return Decision(
            level=DecisionLevel.L3_ESCALATE,
            score=score,
            reason=f"score {score} >= {l2_hi} or high-confidence TI on critical asset",
            skip_llm=False,
            fast_llm_only=True,
            auto_verdict="malicious",
            auto_severity="high",
        )

    # L2 — full triage (LLM + enrichment context injected)
    return Decision(
        level=DecisionLevel.L2_TRIAGE,
        score=score,
        reason=f"score {score} in ambiguous band [{l1}–{l2_hi}]",
        skip_llm=False,
        fast_llm_only=False,
    )
