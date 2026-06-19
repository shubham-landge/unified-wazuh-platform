"""Parallel enrichment fan-out for a single alert.

Runs threat-intel, asset, user, and UEBA enrichers concurrently with per-enricher
timeouts. Fail-open — exceptions are captured, not propagated.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from shared.config import settings
from shared.models.alert import Alert

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentResult:
    """Collected enrichment data for one alert."""

    ti: list[dict] = field(default_factory=list)
    asset: list[dict] = field(default_factory=list)
    user: list[dict] = field(default_factory=list)
    ueba: list[dict] = field(default_factory=list)
    geoip: dict | None = None
    vuln: list[dict] = field(default_factory=list)
    watchlist: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    enriched: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ti": self.ti,
            "asset": self.asset,
            "user": self.user,
            "ueba": self.ueba,
            "geoip": self.geoip,
            "vuln": self.vuln,
            "watchlist": self.watchlist,
            "errors": self.errors,
            "enriched": self.enriched,
        }


async def _enrich_ti(session: AsyncSession, alert: Alert) -> list[dict]:
    """Threat-intel enrichment: query known IOCs against the alert's source/dest IPs."""
    results: list[dict] = []
    iocs = set()
    if alert.source_ip:
        iocs.add(("ip", alert.source_ip))
    if alert.destination_ip:
        iocs.add(("ip", alert.destination_ip))
    if alert.file_hash:
        iocs.add(("hash", alert.file_hash))

    if not iocs:
        return results

    try:
        from shared.connectors.ti_alienvault import AlienVaultOTXConnector
        otx = AlienVaultOTXConnector()
        for ioc_type, ioc_value in iocs:
            try:
                data = await otx.lookup(ioc_type if ioc_type == "hash" else "ipv4", ioc_value)
                if data.get("found"):
                    results.append({"ioc": ioc_value, "type": ioc_type, "source": "otx", **data})
            except Exception:
                pass
    except Exception as exc:
        logger.debug("TI enrichment unavailable: %s", exc)

    return results


async def _enrich_asset(session: AsyncSession, alert: Alert) -> list[dict]:
    """Asset enrichment: look up the affected agent in the asset registry."""
    if not alert.agent_id:
        return []

    try:
        from shared.models.asset import Asset
        from sqlalchemy import select

        result = await session.execute(
            select(Asset).where(Asset.agent_id == alert.agent_id)
        )
        asset = result.scalar_one_or_none()
        if asset:
            return [{
                "agent_id": asset.agent_id,
                "name": getattr(asset, "agent_name", None) or alert.agent_name,
                "os_platform": getattr(asset, "os_platform", None),
                "os_version": getattr(asset, "os_version", None),
                "status": getattr(asset, "status", None),
                "criticality": getattr(asset, "criticality_score", None),
            }]
    except Exception as exc:
        logger.debug("Asset enrichment unavailable: %s", exc)

    return []


async def _enrich_user(session: AsyncSession, alert: Alert) -> list[dict]:
    """User-risk enrichment: look up the user identity and risk profile."""
    if not alert.user_name:
        return []

    try:
        from shared.models.user import User
        from sqlalchemy import select

        result = await session.execute(
            select(User).where(User.email == alert.user_name)
        )
        user = result.scalar_one_or_none()
        if user:
            return [{
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "is_active": user.is_active,
                "last_login": user.last_login_at.isoformat() if user.last_login_at else None,
            }]
    except Exception as exc:
        logger.debug("User enrichment unavailable: %s", exc)

    return []


async def _enrich_ueba(session: AsyncSession, alert: Alert) -> list[dict]:
    """UEBA enrichment: fetch recent anomalies for subjects on this alert."""
    subjects = set()
    if alert.user_name:
        subjects.add(("user", alert.user_name))
    if alert.source_ip:
        subjects.add(("ip", alert.source_ip))
    if alert.agent_id:
        subjects.add(("agent", alert.agent_id))

    if not subjects:
        return []

    try:
        from shared.models.ueba import UebaAnomaly
        from sqlalchemy import select

        subject_types = list({s[0] for s in subjects})
        subject_ids = list({s[1] for s in subjects})
        result = await session.execute(
            select(UebaAnomaly)
            .where(
                UebaAnomaly.subject_type.in_(subject_types),
                UebaAnomaly.subject_id.in_(subject_ids),
            )
            .order_by(UebaAnomaly.created_at.desc())
            .limit(10)
        )
        anomalies = result.scalars().all()
        return [
            {
                "subject_type": a.subject_type,
                "subject_id": a.subject_id,
                "anomaly_type": a.anomaly_type,
                "zscore": a.zscore,
                "severity": a.severity,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in anomalies
        ]
    except Exception as exc:
        logger.debug("UEBA enrichment unavailable: %s", exc)

    return []


async def _enrich_geoip(session: AsyncSession, alert: Alert) -> dict | None:
    """GeoIP stub — returns None when disabled or unavailable."""
    if not settings.enricher_geoip_enabled:
        return None
    try:
        from shared.enrichment.geoip import lookup
        ip = alert.source_ip or alert.destination_ip
        if ip:
            return await lookup(ip)
    except Exception as exc:
        logger.debug("GeoIP enrichment unavailable: %s", exc)
    return None


async def _enrich_vuln(session: AsyncSession, alert: Alert) -> list[dict]:
    """Vulnerability correlation stub."""
    if not settings.enricher_vuln_correlate_enabled:
        return []
    try:
        from shared.enrichment.vuln_correlate import correlate
        return await correlate(session, alert)
    except Exception as exc:
        logger.debug("Vuln correlation unavailable: %s", exc)
    return []


async def _enrich_watchlists(session: AsyncSession, alert: Alert) -> list[dict]:
    """Watchlist hit stub."""
    if not settings.enricher_watchlists_enabled:
        return []
    try:
        from shared.enrichment.watchlists import check
        return await check(session, alert)
    except Exception as exc:
        logger.debug("Watchlist check unavailable: %s", exc)
    return []


async def _run_with_timeout(coro, timeout: int, label: str) -> Any:
    """Run a coroutine with a timeout; return empty result on timeout/error."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("Enricher %s timed out after %ds", label, timeout)
        return None
    except Exception as exc:
        logger.warning("Enricher %s failed: %s", label, exc)
        return None


async def enrich_alert(
    session: AsyncSession,
    alert: Alert,
    redis_client=None,
) -> EnrichmentResult:
    """Run all enrichers in parallel and return an EnrichmentResult.

    Each enricher is capped at `settings.enrichment_timeout_seconds` (default 10s).
    Fail-open: individual failures are logged, not propagated.

    Args:
        session: Async database session.
        alert: The alert to enrich.
        redis_client: Optional Redis client (reserved for future caching use).

    Returns:
        EnrichmentResult with collected data and any errors.
    """
    result = EnrichmentResult()

    if settings.enrichment_kill_switch:
        result.enriched = False
        return result

    timeout = settings.enrichment_timeout_seconds

    # Collect tasks with labels for dynamic mapping.
    task_specs: list[tuple[str, Any]] = [
        ("ti", _run_with_timeout(_enrich_ti(session, alert), timeout, "ti")),
        ("asset", _run_with_timeout(_enrich_asset(session, alert), timeout, "asset")),
        ("user", _run_with_timeout(_enrich_user(session, alert), timeout, "user")),
        ("ueba", _run_with_timeout(_enrich_ueba(session, alert), timeout, "ueba")),
    ]

    if settings.enricher_geoip_enabled:
        task_specs.append(("geoip", _run_with_timeout(_enrich_geoip(session, alert), timeout, "geoip")))
    if settings.enricher_vuln_correlate_enabled:
        task_specs.append(("vuln", _run_with_timeout(_enrich_vuln(session, alert), timeout, "vuln")))
    if settings.enricher_watchlists_enabled:
        task_specs.append(("watchlist", _run_with_timeout(_enrich_watchlists(session, alert), timeout, "watchlists")))

    labels = [spec[0] for spec in task_specs]
    coros = [spec[1] for spec in task_specs]
    gathered = await asyncio.gather(*coros, return_exceptions=True)

    field_map = {
        "ti": "ti", "asset": "asset", "user": "user", "ueba": "ueba",
        "geoip": "geoip", "vuln": "vuln", "watchlist": "watchlist",
    }

    for label, raw in zip(labels, gathered):
        if isinstance(raw, Exception):
            result.errors.append(f"{label}: {raw}")
            continue
        if raw is None:
            continue
        field = field_map[label]
        if label in ("geoip",):
            setattr(result, field, raw)
        elif isinstance(raw, list):
            existing = getattr(result, field)
            if isinstance(existing, list) and raw:
                setattr(result, field, existing + raw)

    result.enriched = True
    return result
