import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.alert import Alert
from shared.models.ueba import UebaAnomaly
from shared.ueba.baseline import update_baseline, compute_z_score

logger = logging.getLogger(__name__)

SEVERITY_THRESHOLDS = [
    (3.0, "critical"),
    (2.5, "high"),
    (2.0, "medium"),
    (1.5, "low"),
]


def _severity_from_z(z: float) -> str:
    for threshold, sev in SEVERITY_THRESHOLDS:
        if z >= threshold:
            return sev
    return "info"


async def process_alert(
    session: AsyncSession,
    alert: Alert,
    tenant_id,
) -> list[UebaAnomaly]:
    anomalies: list[UebaAnomaly] = []
    entities = _extract_entities(alert)

    for entity_type, entity_value in entities:
        bl_count = await update_baseline(
            session, entity_type, entity_value, "alert_count", 1.0, tenant_id=tenant_id
        )
        z = compute_z_score(bl_count, float(bl_count.n))
        if z >= 1.5:
            anomaly = UebaAnomaly(
                tenant_id=tenant_id,
                subject_type=entity_type,
                subject_id=entity_value,
                anomaly_type="alert_count_anomaly",
                score=z,
                severity=_severity_from_z(z),
                description=(
                    f"Alert count anomaly for {entity_type} '{entity_value}': "
                    f"z={z:.2f}, count={bl_count.n}"
                ),
                features={
                    "observed_value": float(bl_count.n),
                    "baseline_mean": bl_count.mean,
                    "baseline_stddev": bl_count.stddev,
                    "z_score": z,
                    "metric": "alert_count",
                },
            )
            session.add(anomaly)
            anomalies.append(anomaly)
            logger.info(
                "UEBA anomaly: %s '%s' metric=alert_count z=%.2f severity=%s",
                entity_type, entity_value, z, anomaly.severity,
            )

        if hasattr(alert, "rule_level") and alert.rule_level:
            bl_level = await update_baseline(
                session, entity_type, entity_value, "rule_level", float(alert.rule_level), tenant_id=tenant_id
            )
            z_level = compute_z_score(bl_level, float(alert.rule_level))
            if z_level >= 2.0:
                anomaly = UebaAnomaly(
                    tenant_id=tenant_id,
                    subject_type=entity_type,
                    subject_id=entity_value,
                    anomaly_type="rule_level_anomaly",
                    score=z_level,
                    severity=_severity_from_z(z_level),
                    description=(
                        f"Rule level anomaly for {entity_type} '{entity_value}': "
                        f"z={z_level:.2f}, rule_level={alert.rule_level}"
                    ),
                    features={
                        "observed_value": float(alert.rule_level),
                        "baseline_mean": bl_level.mean,
                        "baseline_stddev": bl_level.stddev,
                        "z_score": z_level,
                        "metric": "rule_level",
                    },
                )
                session.add(anomaly)
                anomalies.append(anomaly)

    return anomalies


def _extract_entities(alert: Alert) -> list[tuple[str, str]]:
    entities = []
    if alert.agent_id:
        entities.append(("agent", alert.agent_id))
    if alert.agent_ip:
        entities.append(("ip", alert.agent_ip))
    if alert.source_ip:
        entities.append(("source_ip", alert.source_ip))
    if alert.user_name:
        entities.append(("user", alert.user_name))
    return entities