"""Kill-chain stage computation.

Determines the current kill-chain stage of an incident from its member
alerts' MITRE tactics. Appends to stage_history when the stage advances.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.alert import Alert
from shared.models.alert_dedup import AlertIncident
from shared.models.entity import AlertEntity, IncidentEntity

logger = logging.getLogger(__name__)

TACTIC_TO_STAGE = {
    "initial-access": "initial_access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege_escalation",
    "defense-evasion": "defense_evasion",
    "credential-access": "credential_access",
    "discovery": "discovery",
    "lateral-movement": "lateral_movement",
    "collection": "collection",
    "command-and-control": "command_and_control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}

ADVANCING_STAGES = {"lateral_movement", "exfiltration", "impact"}

STAGE_ORDER = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]


def _tactic_to_stage(tactic: str) -> str:
    t = (tactic or "").strip().lower().replace(" ", "-").replace("_", "-")
    return TACTIC_TO_STAGE.get(t, "unknown")


def _stage_index(stage: str) -> int:
    try:
        return STAGE_ORDER.index(stage)
    except ValueError:
        return -1


def _is_advancement(current: str, candidate: str) -> bool:
    return _stage_index(candidate) > _stage_index(current)


async def compute_killchain_stage(
    session: AsyncSession,
    incident: AlertIncident,
) -> str:
    """Compute the current kill-chain stage from member alerts.

    Returns the furthest-advanced stage and appends to stage_history
    if this represents an advancement.
    """
    stmt = (
        select(Alert.mitre_tactic)
        .join(AlertEntity, AlertEntity.alert_id == Alert.id)
        .join(IncidentEntity, IncidentEntity.entity_id == AlertEntity.entity_id)
        .where(IncidentEntity.incident_id == incident.id)
        .where(Alert.mitre_tactic.isnot(None))
        .distinct()
    )
    result = await session.execute(stmt)
    member_tactics = [row[0] for row in result.all()]

    if not member_tactics:
        stmt2 = (
            select(Alert.mitre_tactic)
            .join(AlertEntity, AlertEntity.alert_id == Alert.id)
            .where(AlertEntity.alert_id == Alert.id)
            .where(Alert.mitre_tactic.isnot(None))
            .order_by(Alert.created_at.desc())
            .limit(10)
        )
        result2 = await session.execute(stmt2)
        member_tactics = [row[0] for row in result2.all()]

    if not member_tactics:
        return incident.kill_chain_stage or "unknown"

    stages = [_tactic_to_stage(t) for t in member_tactics]
    furthest = max(stages, key=_stage_index)

    current = incident.kill_chain_stage or "unknown"
    if _is_advancement(current, furthest):
        history = list(incident.stage_history or [])
        history.append({
            "from": current,
            "to": furthest,
            "at": datetime.now(timezone.utc).isoformat(),
            "tactics_found": member_tactics,
        })
        incident.stage_history = history
        incident.kill_chain_stage = furthest
        logger.info(
            "Kill-chain stage advanced: %s -> %s (incident=%s)",
            current, furthest, incident.id,
        )

    return incident.kill_chain_stage


def is_advancing(stage: str) -> bool:
    """True if this stage represents active lateral movement or exfiltration."""
    return (stage or "").lower() in ADVANCING_STAGES
