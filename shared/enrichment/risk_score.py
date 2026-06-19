"""Deterministic risk score engine (0–100, additive, config-driven weights).

All weights are tunable via RISK_WEIGHT_* env vars. Allowlist forces score to 0.
Crown-jewel assets apply a multiplier last. Fail-open: missing enrichment = 0 points.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from shared.config import settings

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentContext:
    """Collected signals from all enrichers, passed into the score engine."""
    # Wazuh
    rule_level: int = 0

    # Threat intelligence
    ti_confidence: float = 0.0          # 0.0 = no hit, 1.0 = confirmed malicious
    ti_is_kev: bool = False             # Known Exploited Vulnerability
    ti_is_known_bad: bool = False       # Explicit blocklist hit

    # Asset criticality
    asset_criticality: int = 0          # 1–10; 0 = unknown
    is_crown_jewel: bool = False        # asset_criticality >= 9 or explicit flag

    # Vulnerability correlation
    vuln_matched: bool = False          # exploit alert matched open CVE on target
    vuln_epss: float = 0.0             # EPSS score (0–1) of matched CVE
    vuln_is_kev: bool = False           # matched CVE is in CISA KEV

    # UEBA
    ueba_zscore: float = 0.0           # highest z-score for this entity/user
    user_is_privileged: bool = False
    user_is_service_acct_interactive: bool = False
    user_is_dormant_reactivated: bool = False

    # GeoIP / IP reputation
    geo_impossible_travel: bool = False
    geo_tor_vpn: bool = False
    geo_bad_asn: bool = False
    geo_unexpected_country: bool = False

    # MITRE
    mitre_high_impact: bool = False     # ransomware / lateral / exfil techniques

    # Allowlist/corrections
    is_allowlisted: bool = False
    is_confirmed_fp: bool = False       # analyst marked as FP in feedback
    is_benign_noise: bool = False       # matches known benign pattern

    # Score breakdown (populated by compute())
    breakdown: dict = field(default_factory=dict)


def _w(name: str, default: float) -> float:
    """Read a RISK_WEIGHT_* env var, falling back to default."""
    return float(getattr(settings, f"risk_weight_{name}", default))


def compute(ctx: EnrichmentContext) -> int:
    """Compute the deterministic 0–100 risk score.

    Returns the integer score and populates ctx.breakdown with per-signal
    contributions for auditability.
    """
    breakdown: dict[str, float] = {}

    # Allowlist → force 0, no further scoring
    if ctx.is_allowlisted:
        ctx.breakdown = {"allowlisted": True}
        return 0

    # ── Rule level ──────────────────────────────────────────────────────────
    level = ctx.rule_level
    if level >= 14:
        pts = _w("rule_level_critical", 40)
    elif level >= 12:
        pts = _w("rule_level_high", 30)
    elif level >= 10:
        pts = _w("rule_level_medium_high", 20)
    elif level >= 7:
        pts = _w("rule_level_medium", 10)
    else:
        pts = 0
    breakdown["rule_level"] = pts
    score = pts

    # ── Threat intelligence ──────────────────────────────────────────────────
    if ctx.ti_is_known_bad or ctx.ti_is_kev:
        pts = _w("ti_known_bad", 40)
    elif ctx.ti_confidence > 0:
        pts = _w("ti_base", 30) * ctx.ti_confidence
    else:
        pts = 0
    breakdown["threat_intel"] = pts
    score += pts

    # ── Asset criticality ────────────────────────────────────────────────────
    crit = min(ctx.asset_criticality, 10)
    pts = _w("asset_criticality_per_point", 2) * crit
    breakdown["asset_criticality"] = pts
    score += pts

    # ── Vulnerability correlation ────────────────────────────────────────────
    if ctx.vuln_matched:
        if ctx.vuln_is_kev or ctx.vuln_epss >= 0.5:
            pts = _w("vuln_kev_epss", 35)
        else:
            pts = _w("vuln_matched", 25)
    else:
        pts = 0
    breakdown["vuln_correlation"] = pts
    score += pts

    # ── UEBA z-score ─────────────────────────────────────────────────────────
    z = ctx.ueba_zscore
    if z >= _w("ueba_zscore_critical_threshold", 5.0):
        pts = _w("ueba_critical", 20)
    elif z >= _w("ueba_zscore_high_threshold", 3.5):
        pts = _w("ueba_high", 12)
    elif z >= _w("ueba_zscore_medium_threshold", 2.5):
        pts = _w("ueba_medium", 6)
    else:
        pts = 0
    breakdown["ueba_zscore"] = pts
    score += pts

    # ── User risk factors ────────────────────────────────────────────────────
    user_pts = 0.0
    if ctx.user_is_privileged:
        user_pts += _w("user_privileged", 10)
    if ctx.user_is_service_acct_interactive:
        user_pts += _w("user_service_acct", 10)
    if ctx.user_is_dormant_reactivated:
        user_pts += _w("user_dormant", 15)
    breakdown["user_risk"] = user_pts
    score += user_pts

    # ── GeoIP / IP reputation ────────────────────────────────────────────────
    geo_pts = 0.0
    if ctx.geo_impossible_travel:
        geo_pts += _w("geo_impossible_travel", 15)
    if ctx.geo_tor_vpn:
        geo_pts += _w("geo_tor_vpn", 8)
    if ctx.geo_bad_asn:
        geo_pts += _w("geo_bad_asn", 5)
    if ctx.geo_unexpected_country:
        geo_pts += _w("geo_unexpected_country", 5)
    breakdown["geo_ip"] = geo_pts
    score += geo_pts

    # ── MITRE technique ──────────────────────────────────────────────────────
    if ctx.mitre_high_impact:
        pts = _w("mitre_high_impact", 10)
        breakdown["mitre"] = pts
        score += pts

    # ── Negative modifiers ───────────────────────────────────────────────────
    if ctx.is_confirmed_fp:
        neg = _w("confirmed_fp_penalty", 20)
        breakdown["confirmed_fp"] = -neg
        score -= neg
    if ctx.is_benign_noise:
        neg = _w("benign_noise_penalty", 10)
        breakdown["benign_noise"] = -neg
        score -= neg

    # ── Crown-jewel multiplier (applied last) ────────────────────────────────
    if ctx.is_crown_jewel and score > 0:
        mult = _w("crown_jewel_multiplier", 1.3)
        breakdown["crown_jewel_mult"] = mult
        score = score * mult

    final = max(0, min(100, round(score)))
    ctx.breakdown = breakdown
    return final
