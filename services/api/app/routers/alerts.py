import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from starlette.status import HTTP_404_NOT_FOUND

from app.db import get_db
from shared.models.alert import Alert
from app.middleware.auth import validate_api_key

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/recent")
async def get_recent_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    min_level: int = Query(default=0, ge=0, le=15),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    query = (
        select(Alert)
        .where(Alert.rule_level >= min_level)
        .order_by(desc(Alert.ingested_at))
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(query)
    alerts = result.scalars().all()

    return {
        "status": "success",
        "count": len(alerts),
        "alerts": [
            {
                "id": str(a.id),
                "rule_id": a.rule_id,
                "rule_description": a.rule_description,
                "rule_level": a.rule_level,
                "rule_groups": a.rule_groups,
                "agent_name": a.agent_name,
                "source_ip": a.source_ip,
                "user_name": a.user_name,
                "mitre_technique": a.mitre_technique,
                "severity": _severity_from_level(a.rule_level),
                "timestamp": a.alert_timestamp.isoformat() if a.alert_timestamp else None,
                "ingested_at": a.ingested_at.isoformat(),
            }
            for a in alerts
        ],
    }


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    try:
        uid = uuid.UUID(alert_id)
    except ValueError:
        uid = alert_id

    if isinstance(uid, uuid.UUID):
        query = select(Alert).where(Alert.id == uid)
    else:
        query = select(Alert).where(Alert.wazuh_alert_id == alert_id)

    result = await db.execute(query)
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Alert not found")

    return {
        "status": "success",
        "alert": {
            "id": str(alert.id),
            "wazuh_alert_id": alert.wazuh_alert_id,
            "rule_id": alert.rule_id,
            "rule_description": alert.rule_description,
            "rule_level": alert.rule_level,
            "rule_groups": alert.rule_groups,
            "mitre_tactic": alert.mitre_tactic,
            "mitre_technique": alert.mitre_technique,
            "agent_id": alert.agent_id,
            "agent_name": alert.agent_name,
            "agent_ip": alert.agent_ip,
            "source_ip": alert.source_ip,
            "source_port": alert.source_port,
            "destination_ip": alert.destination_ip,
            "destination_port": alert.destination_port,
            "protocol": alert.protocol,
            "user_name": alert.user_name,
            "process_name": alert.process_name,
            "file_name": alert.file_name,
            "file_hash": alert.file_hash,
            "event_id": alert.event_id,
            "timestamp": alert.alert_timestamp.isoformat() if alert.alert_timestamp else None,
            "ingested_at": alert.ingested_at.isoformat(),
        },
    }


def _severity_from_level(level: int | None) -> str:
    if level is None:
        return "unknown"
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"
