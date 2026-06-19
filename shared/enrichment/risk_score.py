"""Risk scoring engine for enriched alerts.

Computes an additive score 0-100 using config-driven weights from settings.
Each factor contributes a bounded sub-score; the sum is capped at 100.
"""

import logging
from typing import Any

from shared.config import settings
from shared.models.alert import Alert
from shared.enrichment.pipeline import EnrichmentResult

logger = logging.getLogger(__name__)


def _normalize(value: float, floor: float, ceil: float) -> float:
    """Clamp a value into [floor, ceil]."""
    return max(floor, min(ceil, value))


def _factor_ti(enrichment: EnrichmentResult) -> float:
    """Threat-intel factor: bonus for each confirmed IOC hit."""
    if not enrichment.ti:
        return 0.0
    # Each TI hit contributes up to 5 points, capped at 25.
    raw = min(len(enrichment.ti) * 5, 25)
    # Amplify if any hit has malware families or high pulse count.
    for hit in enrichment.ti:
        if hit.get("malware_families"):
            raw = min(raw + 5, 25)
            break
        if hit.get("pulse_count", 0) >= 5:
            raw = min(raw + 3, 25)
            break
    return _normalize(raw, 0, 25)


def _factor_asset(enrichment: EnrichmentResult) -> float:
    """Asset criticality factor."""
    if not enrichment.asset:
        return 0.0
    criticality = enrichment.asset[0].get("criticality")
    if criticality is not None:
        try:
            val = float(criticality)
            return _normalize(val * 2.5, 0, 15)
        except (TypeError, ValueError):
            pass
    # Fallback: one asset hit = base 5.
    return 5.0


def _factor_user(enrichment: EnrichmentResult) -> float:
    """User risk factor: inactive or absent user is riskier."""
    if not enrichment.user:
        return 5.0  # Unknown user = moderate risk.
    user = enrichment.user[0]
    if not user.get("is_active", True):
        return 10.0  # Inactive account used = elevated risk.
    if user.get("last_login") is None:
        return 5.0  # Never logged in before = suspicious.
    return 2.0  # Known active user = low risk.


def _factor_ueba(enrichment: EnrichmentResult) -> float:
    """UEBA anomaly factor."""
    if not enrichment.ueba:
        return 0.0
    score = 0.0
    for anomaly in enrichment.ueba:
        z = anomaly.get("zscore", 0) or 0
        if z >= 5.0:
            score += 10
        elif z >= 3.0:
            score += 6
        elif z >= 2.0:
            score += 3
        else:
            score += 1
    return _normalize(score, 0, 25)


def _factor_rule_level(alert: Alert) -> float:
    """Rule-level factor: normalise 0-15 Wazuh level into 0-15 contribution."""
    if alert.rule_level is None:
        return 2.0
    level = float(alert.rule_level)
    # Levels 0-15 map linearly; levels above 15 cap at 15.
    return _normalize(level, 0, 15)


def compute_risk_score(alert: Alert, enrichment: EnrichmentResult) -> dict[str, Any]:
    """Compute an additive risk score 0-100 with a breakdown dict.

    Weights are read from settings and should total ~100 for intuitive scaling.
    Each factor is computed independently, multiplied by its weight, summed,
    and capped at 100.

    Returns a dict with keys:
        - score: int (0-100)
        - breakdown: dict of factor_name -> {raw, weight, contribution}
    """
    factors = {
        "ti": (_factor_ti(enrichment), settings.enrichment_risk_weight_ti),
        "asset": (_factor_asset(enrichment), settings.enrichment_risk_weight_asset),
        "user": (_factor_user(enrichment), settings.enrichment_risk_weight_user),
        "ueba": (_factor_ueba(enrichment), settings.enrichment_risk_weight_ueba),
        "rule_level": (_factor_rule_level(alert), settings.enrichment_risk_weight_rule_level),
    }

    total = 0.0
    breakdown = {}

    for name, (raw, weight) in factors.items():
        contribution = (raw / 25.0) * weight if raw > 0 else 0.0
        contribution = round(contribution, 2)
        total += contribution
        breakdown[name] = {
            "raw": raw,
            "weight": weight,
            "contribution": contribution,
        }

    score = int(min(100.0, round(total)))
    return {"score": score, "breakdown": breakdown}
