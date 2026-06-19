"""Cross-domain alert stitching engine.

Links alerts that share an entity into one AlertIncident — regardless of
source_type. Supersedes the old endpoint-only group_key approach while
preserving the existing noise_reduction.evaluate() contract.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from shared.config import settings
from shared.models.alert import Alert
from shared.models.alert_dedup import AlertIncident
from shared.models.entity import Entity, AlertEntity, IncidentEntity
from shared.correlation.entities import extract_entities, ExtractedEntity

logger = logging.getLogger(__name__)

DOMAIN_ENDPOINT = "endpoint"
DOMAIN_IDENTITY = "identity"
DOMAIN_CLOUD = "cloud"
DOMAIN_NETWORK = "network"
DOMAIN_SAAS = "saas"

DOMAIN_LOOKBACK_HOURS = 6


async def _find_or_create_entity(
    session: AsyncSession,
    entity_type: str,
    value: str,
    tenant_id: uuid.UUID,
) -> Entity:
    stmt = select(Entity).where(
        Entity.tenant_id == tenant_id,
        Entity.entity_type == entity_type,
        Entity.value == value,
    )
    result = await session.execute(stmt)
    entity = result.scalar_one_or_none()

    if entity:
        entity.last_seen = datetime.now(timezone.utc)
        return entity

    entity = Entity(
        tenant_id=tenant_id,
        entity_type=entity_type,
        value=value,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    session.add(entity)
    await session.flush()
    return entity


async def _find_incumbent_incident(
    session: AsyncSession,
    entity_ids: list[uuid.UUID],
    lookback: datetime,
) -> AlertIncident | None:
    if not entity_ids:
        return None

    stmt = (
        select(AlertIncident)
        .join(IncidentEntity, IncidentEntity.incident_id == AlertIncident.id)
        .where(
            IncidentEntity.entity_id.in_(entity_ids),
            AlertIncident.status == "open",
            AlertIncident.first_alert_at >= lookback,
        )
        .order_by(AlertIncident.last_alert_at.desc())
        .limit(1)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def _link_entities_to_incident(
    session: AsyncSession,
    incident: AlertIncident,
    entity_ids: list[uuid.UUID],
):
    existing = set()
    existing_result = await session.execute(
        select(IncidentEntity.entity_id).where(
            IncidentEntity.incident_id == incident.id,
            IncidentEntity.entity_id.in_(entity_ids),
        )
    )
    for row in existing_result.all():
        existing.add(row[0])

    for eid in entity_ids:
        if eid not in existing:
            session.add(IncidentEntity(incident_id=incident.id, entity_id=eid))


async def stitch_incident(
    session: AsyncSession,
    alert: Alert,
    tenant_id: uuid.UUID,
) -> AlertIncident:
    """Stitch an alert into a cross-domain incident.

    Extracts entities, links them, finds or creates an AlertIncident
    that shares at least one entity. Sets cross_domain and source_domains.
    """
    extracted = extract_entities(alert)

    entity_ids: list[uuid.UUID] = []
    for ent in extracted:
        if not ent.value:
            continue
        entity = await _find_or_create_entity(session, ent.entity_type, ent.value, tenant_id)
        entity_ids.append(entity.id)

        existing_ae = await session.execute(
            select(AlertEntity).where(
                AlertEntity.alert_id == alert.id,
                AlertEntity.entity_id == entity.id,
                AlertEntity.role == ent.role,
            )
        )
        if not existing_ae.scalar_one_or_none():
            session.add(AlertEntity(alert_id=alert.id, entity_id=entity.id, role=ent.role))

    if not entity_ids:
        return await _create_new_incident(session, alert, tenant_id)

    lookback = datetime.now(timezone.utc) - timedelta(hours=DOMAIN_LOOKBACK_HOURS)
    incident = await _find_incumbent_incident(session, entity_ids, lookback)

    if incident:
        incident.alert_count += 1
        incident.last_alert_at = datetime.now(timezone.utc)
        if alert.rule_level and (not hasattr(incident, "highest_level") or alert.rule_level > getattr(incident, "highest_level", 0)):
            setattr(incident, "highest_level", alert.rule_level)
        await _link_entities_to_incident(session, incident, entity_ids)
        await _update_incident_domains(session, incident)
        return incident

    return await _create_new_incident(session, alert, tenant_id, entity_ids)


async def _create_new_incident(
    session: AsyncSession,
    alert: Alert,
    tenant_id: uuid.UUID,
    entity_ids: list[uuid.UUID] | None = None,
) -> AlertIncident:
    source_type = getattr(alert, "source_type", DOMAIN_ENDPOINT) or DOMAIN_ENDPOINT

    group_key_parts = []
    if alert.source_ip:
        group_key_parts.append(f"src:{alert.source_ip}")
    if alert.user_name:
        group_key_parts.append(f"user:{alert.user_name}")
    if alert.mitre_technique:
        group_key_parts.append(f"technique:{alert.mitre_technique}")
    group_key = "|".join(group_key_parts) or f"rule:{alert.rule_id}"

    severity_map = {12: "critical", 10: "high", 7: "medium", 5: "low"}
    severity = None
    if alert.rule_level:
        for threshold, label in sorted(severity_map.items(), reverse=True):
            if alert.rule_level >= threshold:
                severity = label
                break

    incident = AlertIncident(
        tenant_id=tenant_id,
        group_key=group_key,
        rule_id=alert.rule_id,
        rule_description=alert.rule_description,
        agent_id=alert.agent_id,
        source_ip=alert.source_ip,
        alert_count=1,
        severity=severity,
        status="open",
        first_alert_at=datetime.now(timezone.utc),
        last_alert_at=datetime.now(timezone.utc),
        cross_domain=False,
        source_domains=[source_type],
        kill_chain_stage="unknown",
        stage_history=[],
    )
    session.add(incident)
    await session.flush()

    if entity_ids:
        await _link_entities_to_incident(session, incident, entity_ids)
        await _update_incident_domains(session, incident)

    return incident


async def _update_incident_domains(session: AsyncSession, incident: AlertIncident):
    domain_set = set(incident.source_domains or [])

    stmt = (
        select(Alert.source_type)
        .join(AlertEntity, AlertEntity.alert_id == Alert.id)
        .join(IncidentEntity, IncidentEntity.entity_id == AlertEntity.entity_id)
        .where(IncidentEntity.incident_id == incident.id)
        .where(Alert.source_type.isnot(None))
        .distinct()
    )
    result = await session.execute(stmt)
    for row in result.all():
        domain_set.add(row[0] or DOMAIN_ENDPOINT)

    incident.source_domains = sorted(domain_set)
    incident.cross_domain = len(domain_set) > 1
