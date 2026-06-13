"""Alert deduplication and correlation utilities."""
import hashlib
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.alert import Alert
from shared.models.alert_dedup import AlertIncident
from shared.config import settings

logger = logging.getLogger(__name__)


def make_group_key(rule_id: int | None, agent_id: str | None, source_ip: str | None) -> str:
    """Create deterministic group key for alert correlation."""
    parts = [str(rule_id or ""), str(agent_id or ""), str(source_ip or "")]
    combined = "|".join(parts)
    return hashlib.md5(combined.encode()).hexdigest()


async def get_or_create_incident(
    session: AsyncSession,
    alert: Alert,
    tenant_id: str | None,
    correlation_window_minutes: int = 120,
) -> AlertIncident:
    """
    Find or create an AlertIncident for this alert.
    Groups by (rule_id, agent_id, source_ip) within a time window.
    """
    group_key = make_group_key(alert.rule_id, alert.agent_id, alert.source_ip)
    window_start = datetime.now(timezone.utc) - timedelta(minutes=correlation_window_minutes)

    # Look for an existing incident in the correlation window
    result = await session.execute(
        select(AlertIncident).where(
            AlertIncident.group_key == group_key,
            AlertIncident.tenant_id == tenant_id,
            AlertIncident.last_alert_at >= window_start,
            AlertIncident.status != "closed",
        )
    )
    incident = result.scalar_one_or_none()

    if incident:
        # Update existing incident
        incident.alert_count += 1
        incident.last_alert_at = datetime.now(timezone.utc)
        logger.debug("Alert correlated to incident %s (count=%d)", incident.id, incident.alert_count)
        return incident

    # Create new incident
    incident = AlertIncident(
        tenant_id=tenant_id,
        group_key=group_key,
        rule_id=alert.rule_id,
        rule_description=alert.rule_description,
        agent_id=alert.agent_id,
        source_ip=alert.source_ip,
        alert_count=1,
        severity=_infer_severity(alert),
        first_alert_at=datetime.now(timezone.utc),
        last_alert_at=datetime.now(timezone.utc),
        correlation_window_minutes=correlation_window_minutes,
    )
    session.add(incident)
    logger.info("Created new incident %s for rule %s from %s", incident.id, alert.rule_id, alert.source_ip)
    return incident


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


async def dedup_alert_before_triage(
    session: AsyncSession,
    alert: Alert,
    tenant_id: str | None,
) -> AlertIncident:
    """
    Main entry point: deduplicate alert and return its incident group.
    Call this BEFORE sending alert to triage.
    """
    if not settings.alert_dedup_enabled:
        # If dedup disabled, create a single-alert incident
        incident = AlertIncident(
            tenant_id=tenant_id,
            group_key=make_group_key(alert.rule_id, alert.agent_id, alert.source_ip),
            rule_id=alert.rule_id,
            rule_description=alert.rule_description,
            agent_id=alert.agent_id,
            source_ip=alert.source_ip,
            alert_count=1,
            severity=_infer_severity(alert),
            first_alert_at=alert.alert_timestamp or datetime.now(timezone.utc),
            last_alert_at=alert.alert_timestamp or datetime.now(timezone.utc),
        )
        session.add(incident)
        return incident

    return await get_or_create_incident(
        session,
        alert,
        tenant_id,
        settings.alert_correlation_window_minutes,
    )
