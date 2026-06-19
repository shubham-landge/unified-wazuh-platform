"""Parallel enrichment fan-out for cross-domain incidents.

Runs threat-intel, asset criticality, user-risk, UEBA anomaly, and RAG
few-shot retrieval concurrently via asyncio.gather — then assembles the
EvidencePack before the triage LLM runs.
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
from shared.models.asset import Asset
from shared.models.ueba import UebaAnomaly
from shared.models.entity import AlertEntity, IncidentEntity

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


async def _enrich_threat_intel(session: AsyncSession, incident: AlertIncident) -> list[dict]:
    try:
        stmt = (
            select(Alert)
            .join(AlertEntity, AlertEntity.alert_id == Alert.id)
            .join(IncidentEntity, IncidentEntity.entity_id == AlertEntity.entity_id)
            .where(IncidentEntity.incident_id == incident.id)
            .where(Alert.source_ip.isnot(None))
            .limit(5)
        )
        result = await session.execute(stmt)
        alerts = result.scalars().all()

        ips = {a.source_ip for a in alerts if a.source_ip}
        if not ips:
            return []

        from shared.connectors.ti_alienvault import AlienVaultOTXConnector
        otx = AlienVaultOTXConnector()
        results = []
        for ip in ips:
            try:
                data = await otx.lookup("ipv4", ip)
                results.append({"ioc": ip, "type": "ip", "otx": data})
            except Exception:
                pass
        return results
    except Exception as exc:
        logger.warning("Threat intel enrichment failed: %s", exc)
        return []


async def _enrich_asset_criticality(session: AsyncSession, incident: AlertIncident) -> list[dict]:
    try:
        stmt = (
            select(Alert.agent_id, Alert.agent_name)
            .join(AlertEntity, AlertEntity.alert_id == Alert.id)
            .join(IncidentEntity, IncidentEntity.entity_id == AlertEntity.entity_id)
            .where(IncidentEntity.incident_id == incident.id)
            .where(Alert.agent_id.isnot(None))
            .limit(10)
        )
        result = await session.execute(stmt)
        rows = result.all()

        agent_ids = {r[0] for r in rows if r[0]}
        if not agent_ids:
            return []

        asset_result = await session.execute(
            select(Asset).where(Asset.agent_id.in_(agent_ids))
        )
        assets = asset_result.scalars().all()

        return [
            {
                "agent_id": a.agent_id,
                "name": a.agent_name,
                "os_platform": a.os_platform,
                "os_version": a.os_version,
                "status": a.status,
                "criticality": getattr(a, "criticality_score", None),
            }
            for a in assets
        ]
    except Exception as exc:
        logger.warning("Asset enrichment failed: %s", exc)
        return []


async def _enrich_user_risk(session: AsyncSession, incident: AlertIncident) -> list[dict]:
    try:
        stmt = (
            select(Alert.user_name)
            .join(AlertEntity, AlertEntity.alert_id == Alert.id)
            .join(IncidentEntity, IncidentEntity.entity_id == AlertEntity.entity_id)
            .where(IncidentEntity.incident_id == incident.id)
            .where(Alert.user_name.isnot(None))
            .distinct()
            .limit(10)
        )
        result = await session.execute(stmt)
        users = [row[0] for row in result.all()]
        if not users:
            return []

        from shared.models.user import User
        user_result = await session.execute(
            select(User).where(User.email.in_(users))
        )
        user_rows = user_result.scalars().all()

        return [
            {
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role,
                "is_active": u.is_active,
                "last_login": u.last_login_at.isoformat() if u.last_login_at else None,
            }
            for u in user_rows
        ]
    except Exception as exc:
        logger.warning("User risk enrichment failed: %s", exc)
        return []


async def _enrich_ueba(session: AsyncSession, incident: AlertIncident) -> list[dict]:
    try:
        stmt = (
            select(Alert.user_name, Alert.source_ip)
            .join(AlertEntity, AlertEntity.alert_id == Alert.id)
            .join(IncidentEntity, IncidentEntity.entity_id == AlertEntity.entity_id)
            .where(IncidentEntity.incident_id == incident.id)
            .limit(10)
        )
        result = await session.execute(stmt)
        rows = result.all()

        subjects = set()
        for row in rows:
            if row[0]:
                subjects.add(("user", row[0]))
            if row[1]:
                subjects.add(("ip", row[1]))

        if not subjects:
            return []

        anomaly_result = await session.execute(
            select(UebaAnomaly)
            .where(
                UebaAnomaly.subject_type.in_([s[0] for s in subjects]),
                UebaAnomaly.subject_id.in_([s[1] for s in subjects]),
            )
            .order_by(UebaAnomaly.created_at.desc())
            .limit(10)
        )
        anomalies = anomaly_result.scalars().all()

        return [
            {
                "subject_type": a.subject_type,
                "subject_id": a.subject_id,
                "anomaly_type": a.anomaly_type,
                "zscore": a.zscore,
                "zscore_threshold": a.zscore_threshold,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in anomalies
        ]
    except Exception as exc:
        logger.warning("UEBA enrichment failed: %s", exc)
        return []


async def _enrich_few_shot(session: AsyncSession, incident: AlertIncident) -> list[dict]:
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
    try:
        stmt = (
            select(IncidentEntity.entity_id)
            .where(IncidentEntity.incident_id == incident.id)
        )
        result = await session.execute(stmt)
        entity_ids = [row[0] for row in result.all()]
        if not entity_ids:
            return []

        related_stmt = (
            select(AlertIncident)
            .join(IncidentEntity, IncidentEntity.incident_id == AlertIncident.id)
            .where(
                IncidentEntity.entity_id.in_(entity_ids),
                AlertIncident.id != incident.id,
                AlertIncident.status == "closed",
            )
            .distinct()
            .order_by(AlertIncident.last_alert_at.desc())
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


async def enrich_incident(
    session: AsyncSession,
    incident: AlertIncident,
) -> EvidencePack:
    """Run all enrichment sources in parallel and assemble an EvidencePack."""
    pack = EvidencePack()

    results = await asyncio.gather(
        _enrich_threat_intel(session, incident),
        _enrich_asset_criticality(session, incident),
        _enrich_user_risk(session, incident),
        _enrich_ueba(session, incident),
        _enrich_few_shot(session, incident),
        _enrich_related_incidents(session, incident),
        return_exceptions=True,
    )

    names = ["threat_intel", "asset_criticality", "user_risk", "ueba_anomalies", "few_shot_examples", "related_incidents"]
    for name, data in zip(names, results):
        if isinstance(data, Exception):
            logger.warning("Enrichment %s failed: %s", name, data)
            continue
        if data:
            setattr(pack, name, data)

    pack.enriched_at = datetime.now(timezone.utc).isoformat()
    incident.first_enriched_at = datetime.now(timezone.utc)
    return pack
