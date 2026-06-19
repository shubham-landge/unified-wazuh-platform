"""Incident-level enrichment that delegates per-alert work to the pipeline.

Queries all alerts attached to an incident, runs `shared.enrichment.pipeline.enrich_alert`
for each one in parallel, then deduplicates and aggregates the results into an
`EvidencePack` for backward compatibility with the orchestrator handlers.

Incident-specific enrichers (few-shot examples, related incidents) are still computed
at the incident level and merged into the final pack.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.config import settings
from shared.models.alert import Alert
from shared.models.alert_dedup import AlertIncident
from shared.models.entity import AlertEntity, IncidentEntity
from shared.enrichment.pipeline import enrich_alert

logger = logging.getLogger(__name__)


class EvidencePack:
    """Collected enrichment data for an incident — populated by enrich_incident."""

    def __init__(self):
        self.threat_intel: list[dict] = []
        self.asset_criticality: list[dict] = []
        self.user_risk: list[dict] = []
        self.ueba_anomalies: list[dict] = []
        self.few_shot_examples: list[dict] = []
        self.related_incidents: list[dict] = []
        self.enriched_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_intel": self.threat_intel,
            "asset_criticality": self.asset_criticality,
            "user_risk": self.user_risk,
            "ueba_anomalies": self.ueba_anomalies,
            "few_shot_examples": self.few_shot_examples,
            "related_incidents": self.related_incidents,
            "enriched_at": self.enriched_at,
        }


async def _alerts_for_incident(session: AsyncSession, incident: AlertIncident) -> list[Alert]:
    """Fetch all alerts linked to this incident via entity stitching."""
    try:
        stmt = (
            select(Alert)
            .join(AlertEntity, AlertEntity.alert_id == Alert.id)
            .join(IncidentEntity, IncidentEntity.entity_id == AlertEntity.entity_id)
            .where(IncidentEntity.incident_id == incident.id)
            .order_by(Alert.alert_timestamp.desc())
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
    except Exception as exc:
        logger.warning("Failed to load alerts for incident %s: %s", incident.id, exc)
        return []


async def _enrich_few_shot(session: AsyncSession, incident: AlertIncident) -> list[dict]:
    """Retrieve few-shot examples based on MITRE techniques in the incident."""
    try:
        stmt = (
            select(Alert.mitre_technique)
            .join(AlertEntity, AlertEntity.alert_id == Alert.id)
            .join(IncidentEntity, IncidentEntity.entity_id == AlertEntity.entity_id)
            .where(IncidentEntity.incident_id == incident.id)
            .where(Alert.mitre_technique.isnot(None))
            .distinct()
            .limit(5)
        )
        result = await session.execute(stmt)
        techniques = [row[0] for row in result.all()]

        if not techniques:
            return []

        from shared.rag.few_shot import retrieve
        examples = await retrieve("correlation", {"incident_id": str(incident.id)}, technique_ids=techniques)
        return examples
    except Exception as exc:
        logger.warning("Few-shot enrichment failed: %s", exc)
        return []


async def _enrich_related_incidents(session: AsyncSession, incident: AlertIncident) -> list[dict]:
    """Find related closed incidents that share entities with this one."""
    try:
        stmt = (
            select(IncidentEntity.entity_id)
            .where(IncidentEntity.incident_id == incident.id)
        )
        result = await session.execute(stmt)
        entity_ids = [row[0] for row in result.all()]
        if not entity_ids:
            return []

        from shared.models.alert_dedup import AlertIncident as AI
        related_stmt = (
            select(AI)
            .join(IncidentEntity, IncidentEntity.incident_id == AI.id)
            .where(
                IncidentEntity.entity_id.in_(entity_ids),
                AI.id != incident.id,
                AI.status == "closed",
            )
            .distinct()
            .order_by(AI.last_alert_at.desc())
            .limit(5)
        )
        related_result = await session.execute(related_stmt)
        related = related_result.scalars().all()

        return [
            {
                "incident_id": str(r.id),
                "severity": r.severity,
                "alert_count": r.alert_count,
                "kill_chain_stage": r.kill_chain_stage,
                "closed_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in related
        ]
    except Exception as exc:
        logger.warning("Related incidents enrichment failed: %s", exc)
        return []


def _deduplicate_dicts(items: list[dict], key_fn) -> list[dict]:
    """Deduplicate a list of dicts using a key function, preserving order."""
    seen = set()
    out = []
    for item in items:
        key = key_fn(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


async def enrich_incident(
    session: AsyncSession,
    incident: AlertIncident,
) -> EvidencePack:
    """Run all enrichment sources for an incident and assemble an EvidencePack.

    Per-alert enrichment is delegated to `shared.enrichment.pipeline.enrich_alert`.
    Results are deduplicated and aggregated into the incident-level EvidencePack.
    Incident-specific enrichers (few-shot, related incidents) are computed separately.
    """
    pack = EvidencePack()

    alerts = await _alerts_for_incident(session, incident)
    if not alerts:
        logger.debug("No alerts found for incident %s", incident.id)
        pack.enriched_at = datetime.now(timezone.utc).isoformat()
        return pack

    # Run the alert-level pipeline for each alert in parallel.
    alert_results = await asyncio.gather(
        *[enrich_alert(session, alert) for alert in alerts],
        return_exceptions=True,
    )

    # Aggregate and deduplicate per-field.
    all_ti: list[dict] = []
    all_asset: list[dict] = []
    all_user: list[dict] = []
    all_ueba: list[dict] = []

    for raw in alert_results:
        if isinstance(raw, Exception):
            logger.warning("Alert enrichment failed in incident %s: %s", incident.id, raw)
            continue
        all_ti.extend(raw.ti)
        all_asset.extend(raw.asset)
        all_user.extend(raw.user)
        all_ueba.extend(raw.ueba)

    pack.threat_intel = _deduplicate_dicts(all_ti, lambda d: d.get("ioc", str(d)))
    pack.asset_criticality = _deduplicate_dicts(all_asset, lambda d: d.get("agent_id", str(d)))
    pack.user_risk = _deduplicate_dicts(all_user, lambda d: d.get("email", str(d)))
    pack.ueba_anomalies = _deduplicate_dicts(
        all_ueba, lambda d: (d.get("subject_type"), d.get("subject_id"))
    )

    # Incident-specific enrichers.
    few_shot, related = await asyncio.gather(
        _enrich_few_shot(session, incident),
        _enrich_related_incidents(session, incident),
        return_exceptions=True,
    )

    if not isinstance(few_shot, Exception):
        pack.few_shot_examples = few_shot
    else:
        logger.warning("Few-shot enrichment failed: %s", few_shot)

    if not isinstance(related, Exception):
        pack.related_incidents = related
    else:
        logger.warning("Related incidents enrichment failed: %s", related)

    pack.enriched_at = datetime.now(timezone.utc).isoformat()
    incident.first_enriched_at = datetime.now(timezone.utc)
    return pack
