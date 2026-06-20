"""Parallel enrichment pipeline — fan-out with per-enricher timeouts.

Each enricher runs concurrently. If it times out or raises, its contribution
is 0 (fail-open). The pipeline populates an EnrichmentContext and returns it.

Typical call-site (in triage_worker):
    ctx = await run(alert, tenant_id, session, redis_client)
    score = risk_score.compute(ctx)
    decision = decision_gate.decide(ctx, score, alert.rule_level)
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from shared.enrichment.risk_score import EnrichmentContext
from shared.enrichment import geoip, vuln_correlate, watchlists
from shared.enrichment import ti as ti_enricher
from shared.enrichment import asset as asset_enricher
from shared.enrichment import user as user_enricher
from shared.enrichment import ueba_history as ueba_hist

logger = logging.getLogger(__name__)

# Per-enricher timeout in seconds
_GEO_TIMEOUT = 0.5
_TI_TIMEOUT = 2.0
_ASSET_TIMEOUT = 1.0
_USER_TIMEOUT = 1.0
_VULN_TIMEOUT = 2.0
_UEBA_TIMEOUT = 2.0
_UEBA_HIST_TIMEOUT = 2.0

# High-impact MITRE techniques (ransomware, lateral movement, exfil)
_HIGH_IMPACT_TECHNIQUES = frozenset([
    "T1486", "T1491", "T1490",  # ransomware
    "T1021", "T1210", "T1534", "T1570",  # lateral movement
    "T1041", "T1048", "T1567", "T1537",  # exfiltration
    "T1078", "T1110", "T1552",  # credential access
])


async def _run_geo(ctx: EnrichmentContext, source_ip: Optional[str], user_key: str, redis_client) -> None:
    """Populate GeoIP fields in ctx."""
    try:
        if not source_ip:
            return
        result = geoip.lookup(source_ip)
        if result and not result.is_private:
            ctx.geo_tor_vpn = result.is_tor_vpn
            ctx.geo_bad_asn = result.is_bad_asn
            # Impossible travel check
            if redis_client and result.latitude:
                ctx.geo_impossible_travel = geoip.check_impossible_travel(
                    user_key, result, redis_client
                )
    except Exception as exc:
        logger.debug("geo enricher error: %s", exc)


async def _run_ti(ctx: EnrichmentContext, alert, tenant_id: str, session: AsyncSession) -> None:
    """Populate TI fields using shared/enrichment/ti.py."""
    try:
        source_ip = getattr(alert, "source_ip", None)
        if source_ip:
            is_known_bad, confidence, is_kev = await ti_enricher.lookup(
                session, source_ip, str(tenant_id)
            )
            if is_known_bad:
                ctx.ti_is_known_bad = True
                ctx.ti_confidence = max(ctx.ti_confidence, confidence)
            elif confidence > 0:
                ctx.ti_confidence = max(ctx.ti_confidence, confidence)
            if is_kev:
                ctx.ti_is_kev = True
            # Populate raw result for EvidencePack aggregation
            ctx.ti.append({
                "ioc": source_ip,
                "is_known_bad": is_known_bad,
                "confidence": confidence,
                "is_kev": is_kev,
            })
    except Exception as exc:
        logger.debug("TI enricher error: %s", exc)


async def _run_asset(ctx: EnrichmentContext, alert, tenant_id: str, session: AsyncSession) -> None:
    """Populate asset criticality from shared/enrichment/asset.py."""
    try:
        agent_id = getattr(alert, "agent_id", None)
        if agent_id:
            criticality, is_cj = await asset_enricher.get_asset_criticality(
                session, agent_id, str(tenant_id)
            )
            if criticality > 0:
                ctx.asset_criticality = criticality
            if is_cj:
                ctx.is_crown_jewel = True
            # Populate raw result for EvidencePack aggregation
            ctx.asset.append({
                "agent_id": agent_id,
                "criticality": criticality,
                "is_crown_jewel": is_cj,
            })
    except Exception as exc:
        logger.debug("Asset enricher error: %s", exc)


async def _run_user(ctx: EnrichmentContext, alert, tenant_id: str, session: AsyncSession) -> None:
    """Populate user risk factors from shared/enrichment/user.py."""
    try:
        user_name = getattr(alert, "user_name", None)
        if user_name:
            is_priv, is_svc_acct, is_dormant = await user_enricher.get_user_risk_factors(
                session, user_name, str(tenant_id)
            )
            if is_priv:
                ctx.user_is_privileged = True
            if is_svc_acct:
                ctx.user_is_service_acct_interactive = True
            if is_dormant:
                ctx.user_is_dormant_reactivated = True
            # Populate raw result for EvidencePack aggregation
            ctx.user.append({
                "user_name": user_name,
                "is_privileged": is_priv,
                "is_service_acct_interactive": is_svc_acct,
                "is_dormant_reactivated": is_dormant,
            })
    except Exception as exc:
        logger.debug("User enricher error: %s", exc)


async def _run_ueba(ctx: EnrichmentContext, alert, tenant_id: str, session: AsyncSession) -> None:
    """Populate UEBA z-score from shared UEBA detector."""
    try:
        from shared.ueba.detector import process_alert  # type: ignore
        anomalies = await process_alert(session, alert, str(tenant_id))
        if anomalies:
            ctx.ueba_zscore = max(float(getattr(a, "score", 0.0)) for a in anomalies)
            # Populate raw results for EvidencePack aggregation
            for a in anomalies:
                ctx.ueba.append({
                    "subject_type": getattr(a, "subject_type", "unknown"),
                    "subject_id": getattr(a, "subject_id", "unknown"),
                    "z_score": float(getattr(a, "score", 0.0)),
                    "anomaly_type": getattr(a, "anomaly_type", None),
                })
    except Exception as exc:
        logger.debug("UEBA enricher error: %s", exc)


async def _run_ueba_history(ctx: EnrichmentContext, alert, tenant_id: str, session: AsyncSession) -> None:
    """Populate UEBA historical context from shared/enrichment/ueba_history.py."""
    try:
        agent_id = getattr(alert, "agent_id", None)
        user_name = getattr(alert, "user_name", None)
        source_ip = getattr(alert, "source_ip", None)

        anomalies, max_hist_zscore = await ueba_hist.get_entity_history(
            session, agent_id, user_name, source_ip, str(tenant_id)
        )
        # Boost the UEBA z-score if history shows highly anomalous behavior
        if max_hist_zscore > ctx.ueba_zscore:
            ctx.ueba_zscore = max(ctx.ueba_zscore, max_hist_zscore * 0.8)
        # Populate raw results for EvidencePack aggregation
        for a in anomalies:
            ctx.ueba.append({
                "subject_type": a.get("subject_type", "unknown"),
                "subject_id": a.get("subject_id", "unknown"),
                "z_score": a.get("z_score", 0.0),
                "anomaly_type": a.get("anomaly_type", None),
            })
    except Exception as exc:
        logger.debug("UEBA history enricher error: %s", exc)


async def _run_vuln(ctx: EnrichmentContext, alert, session: AsyncSession) -> None:
    """Populate vulnerability correlation fields."""
    try:
        agent_id = getattr(alert, "agent_id", None)
        desc = getattr(alert, "rule_description", "") or ""
        groups = getattr(alert, "rule_groups", "") or ""
        cve = getattr(alert, "rule_cve", None)
        matched, epss, is_kev = await vuln_correlate.correlate(
            session, agent_id, desc, groups, cve
        )
        ctx.vuln_matched = matched
        ctx.vuln_epss = epss
        ctx.vuln_is_kev = is_kev
    except Exception as exc:
        logger.debug("vuln enricher error: %s", exc)


async def run(
    alert,
    tenant_id: uuid.UUID | str,
    session: AsyncSession,
    redis_client=None,
    watchlist_cache: Optional[watchlists.WatchlistCache] = None,
) -> EnrichmentContext:
    """Run all enrichers in parallel, populate and return EnrichmentContext."""
    ctx = EnrichmentContext(
        rule_level=getattr(alert, "rule_level", 0),
    )
    tenant_str = str(tenant_id)
    source_ip = getattr(alert, "source_ip", None) or ""
    user_name = getattr(alert, "user_name", None) or ""
    agent_id = getattr(alert, "agent_id", None) or ""
    mitre = getattr(alert, "mitre_technique", None) or ""

    # MITRE high-impact check (no I/O)
    if any(mitre.startswith(t) for t in _HIGH_IMPACT_TECHNIQUES):
        ctx.mitre_high_impact = True

    # Watchlist checks (Redis, fast)
    if watchlist_cache:
        indicators = [x for x in [source_ip, user_name, agent_id] if x]
        ctx.is_allowlisted = watchlist_cache.is_allowlisted(tenant_str, indicators)
        if not ctx.is_allowlisted:
            blocked, bl_conf = watchlist_cache.is_blocklisted(tenant_str, indicators)
            if blocked:
                ctx.ti_is_known_bad = True
                ctx.ti_confidence = max(ctx.ti_confidence, bl_conf)
            ctx.is_crown_jewel = watchlist_cache.is_crown_jewel(tenant_str, [agent_id])

    # If allowlisted, skip all I/O enrichers
    if ctx.is_allowlisted:
        return ctx

    user_key = user_name or source_ip or agent_id

    # Fan-out with timeouts — all enrichers run in parallel
    await asyncio.gather(
        asyncio.wait_for(_run_geo(ctx, source_ip, user_key, redis_client), timeout=_GEO_TIMEOUT),
        asyncio.wait_for(_run_ti(ctx, alert, tenant_str, session), timeout=_TI_TIMEOUT),
        asyncio.wait_for(_run_asset(ctx, alert, tenant_str, session), timeout=_ASSET_TIMEOUT),
        asyncio.wait_for(_run_user(ctx, alert, tenant_str, session), timeout=_USER_TIMEOUT),
        asyncio.wait_for(_run_vuln(ctx, alert, session), timeout=_VULN_TIMEOUT),
        asyncio.wait_for(_run_ueba(ctx, alert, tenant_str, session), timeout=_UEBA_TIMEOUT),
        asyncio.wait_for(_run_ueba_history(ctx, alert, tenant_str, session), timeout=_UEBA_HIST_TIMEOUT),
        return_exceptions=True,  # each timeout/error is silenced
    )

    return ctx


# Backward compatibility: origin/main code expects `enrich_alert`
enrich_alert = run
