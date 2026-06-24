"""Hybrid decision fusion — combines LLM verdict with deterministic signals.

Takes the LLM result and enrichment context, applies up to four override
rules based on TI, UEBA, and risk-score signals, and returns an adjusted
verdict with fusion metadata.

Fusion is designed for **L2 triage** results.  L3/L4 verdicts are already
deterministic and should skip fusion at the call site.
"""

from __future__ import annotations

import logging
from typing import Any

from shared.enrichment.risk_score import EnrichmentContext

logger = logging.getLogger(__name__)


def fuse_verdict(
    llm_verdict: dict,
    enrichment_ctx: EnrichmentContext,
    risk_score: int,
) -> dict:
    """Return fused verdict with adjusted severity, confidence, and flags.

    Parameters
    ----------
    llm_verdict:
        Raw dict returned by the LLM provider.  Expected keys include
        ``severity``, ``confidence``, ``category``, etc.
    enrichment_ctx:
        Populated ``EnrichmentContext`` from the enrichment pipeline.
    risk_score:
        Integer risk score (0--100) from ``risk_score.compute()``.

    Returns
    -------
    dict
        A *new* dict (the original ``llm_verdict`` is never mutated) with
        potentially adjusted ``severity`` / ``confidence`` plus two
        fusion-specific keys:

        - ``fusion_applied`` (bool): ``True`` when at least one override fired.
        - ``fusion_overrides`` (list[str]): Human-readable list of rules
          that triggered, empty when no override fired.
    """
    # Copy — never mutate the original LLM verdict
    fused: dict[str, Any] = dict(llm_verdict)
    fused["fusion_applied"] = False
    fused["fusion_overrides"] = []

    severity = fused.get("severity", "medium") or "medium"
    confidence = fused.get("confidence", 0.0) or 0.0
    overrides: list[str] = []

    # ---- Rule 1: benign → suspicious when TI says known-bad ----------------
    if severity == "benign" and enrichment_ctx.ti_is_known_bad:
        severity = "suspicious"
        confidence = max(confidence, 0.8)
        overrides.append(
            "TI is_known_bad overrode benign → suspicious, confidence ≥ 0.8"
        )

    # ---- Rule 2: malicious confidence haircut when signals are weak --------
    if severity == "malicious":
        ueba_low = enrichment_ctx.ueba_zscore < 1.0
        no_ti = (
            not enrichment_ctx.ti_is_known_bad
            and enrichment_ctx.ti_confidence == 0.0
        )
        low_score = risk_score < 20
        if ueba_low and no_ti and low_score:
            confidence = max(0.0, confidence - 0.2)
            overrides.append(
                "Low UEBA z-score, no TI, low risk score → confidence -0.2"
            )

    # ---- Rule 3: boost confidence when risk is high but LLM is unsure -------
    if risk_score >= 60 and confidence < 0.7:
        confidence = 0.75
        overrides.append(
            f"Risk score {risk_score} ≥ 60 with low LLM confidence → boosted to 0.75"
        )

    # ---- Rule 4: critical → high when risk score doesn't support it ---------
    if severity == "critical" and risk_score < 40:
        severity = "high"
        overrides.append(
            f"Risk score {risk_score} < 40 → downgraded critical → high"
        )

    fused["severity"] = severity
    fused["confidence"] = round(confidence, 4)

    if overrides:
        fused["fusion_applied"] = True
        fused["fusion_overrides"] = overrides

    return fused
