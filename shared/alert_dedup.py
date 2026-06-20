"""Alert deduplication and correlation utilities.

This module now delegates to the entity-based incident stitching engine in
`shared.correlation.stitch` and is kept only for backward-compatible imports.
The old hash-based (rule_id, agent_id, source_ip) grouping has been retired.
"""
import logging
import uuid as uuid_mod
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from shared.config import settings
from shared.correlation.stitch import stitch_incident
from shared.models.alert import Alert
from shared.models.alert_dedup import AlertIncident

logger = logging.getLogger(__name__)


def _infer_severity(alert: Alert) -> str:
    """Map rule_level to severity."""
    level = alert.rule_level or 0
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


async def get_or_create_incident(
    session: AsyncSession,
    alert: Alert,
    tenant_id: str | None,
    correlation_window_minutes: int = 120,
) -> AlertIncident:
    """Find or create an entity-based AlertIncident for this alert."""
    if not tenant_id:
        return await _single_alert_incident(session, alert, tenant_id)

    try:
        tenant_uuid = uuid_mod.UUID(str(tenant_id))
        incident = await stitch_incident(session, alert, tenant_uuid)
        # Preserve fields the old API expected
        incident.correlation_window_minutes = correlation_window_minutes
        if not incident.severity:
            incident.severity = _infer_severity(alert)
        return incident
    except Exception as exc:
        logger.warning(
            "stitch_incident failed for alert %s, falling back to single-alert: %s",
            alert.id,
            exc,
        )
        await session.rollback()
        return await _single_alert_incident(session, alert, tenant_id)


async def dedup_alert_before_triage(
    session: AsyncSession,
    alert: Alert,
    tenant_id: str | None,
) -> AlertIncident:
    """
    Main entry point: deduplicate alert and return its incident group.
    Call this BEFORE sending alert to triage.
    """
    if not settings.alert_dedup_enabled or not tenant_id:
        return await _single_alert_incident(session, alert, tenant_id)

    try:
        tenant_uuid = uuid_mod.UUID(str(tenant_id))
        return await stitch_incident(session, alert, tenant_uuid)
    except Exception as exc:
        logger.warning(
            "stitch_incident failed for alert %s, falling back: %s",
            alert.id,
            exc,
        )
        await session.rollback()
        return await _single_alert_incident(session, alert, tenant_id)


async def _single_alert_incident(
    session: AsyncSession,
    alert: Alert,
    tenant_id: str | None,
) -> AlertIncident:
    """Create a standalone incident for a single alert (no entity stitching)."""
    incident = AlertIncident(
        tenant_id=tenant_id,
        group_key=f"single:{alert.id}",
        rule_id=alert.rule_id,
        rule_description=alert.rule_description,
        agent_id=alert.agent_id,
        source_ip=alert.source_ip,
        alert_count=1,
        severity=_infer_severity(alert),
        first_alert_at=alert.alert_timestamp or datetime.now(timezone.utc),
        last_alert_at=alert.alert_timestamp or datetime.now(timezone.utc),
        status="open",
    )
    session.add(incident)
    await session.flush()
    return incident
