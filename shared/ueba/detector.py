"""
UEBA anomaly detector.

For each incoming alert, computes per-entity alert-rate metrics,
updates baselines, and flags anomalies when z-score exceeds threshold.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.alert import Alert
from shared.models.ueba import UebaAnomaly
from shared.ueba.baseline import update_baseline, z_score, stddev
from shared.config import settings

logger = logging.getLogger(__name__)

# Z-score thresholds
_ZSCORE_MEDIUM = float(getattr(settings, "ueba_zscore_medium", 2.5))
_ZSCORE_HIGH = float(getattr(settings, "ueba_zscore_high", 3.5))
_ZSCORE_CRITICAL = float(getattr(settings, "ueba_zscore_critical", 5.0))

# Minimum observations before anomaly detection fires
_MIN_N = int(getattr(settings, "ueba_min_observations", 10))


def _severity_from_zscore(z: float) -> str:
    if z >= _ZSCORE_CRITICAL:
        return "critical"
    if z >= _ZSCORE_HIGH:
        return "high"
    if z >= _ZSCORE_MEDIUM:
        return "medium"
    return "low"


async def analyze_alert(session: AsyncSession, alert: Alert) -> list[UebaAnomaly]:
    """
    Update baselines for the alert's entity metrics and return any new anomalies.
    Metrics tracked:
      - alert_count_1h  per user / per host
      - rule_level      per user
    """
    anomalies = []
    now = datetime.now(timezone.utc)

    # Count alerts for this user/host in the past hour (approximate — query DB)
    entities = []
    if alert.user_name:
        entities.append(("user", alert.user_name))
    if alert.agent_name:
        entities.append(("host", alert.agent_name))

    for entity_type, entity_value in entities:
        # Metric 1: how many alerts for this entity recently (from baseline history)
        observed_count = 1.0   # incremental — each alert adds 1
        bl_count = await update_baseline(
            session, entity_type, entity_value, "alert_count", observed_count
        )
        z = z_score(bl_count, observed_count)

        if bl_count.n >= _MIN_N and z >= _ZSCORE_MEDIUM:
            anomaly = UebaAnomaly(
                alert_id=alert.id,
                entity_type=entity_type,
                entity_value=entity_value,
                metric="alert_count",
                observed_value=observed_count,
                baseline_mean=bl_count.mean,
                baseline_stddev=stddev(bl_count),
                z_score=z,
                severity=_severity_from_zscore(z),
                details={
                    "rule_description": alert.rule_description,
                    "rule_level": alert.rule_level,
                    "source_ip": alert.source_ip,
                },
            )
            session.add(anomaly)
            anomalies.append(anomaly)
            logger.info(
                "UEBA anomaly: %s '%s' metric=alert_count z=%.2f severity=%s",
                entity_type, entity_value, z, anomaly.severity,
            )

        # Metric 2: rule_level deviation
        if alert.rule_level is not None:
            bl_level = await update_baseline(
                session, entity_type, entity_value, "rule_level", float(alert.rule_level)
            )
            z_level = z_score(bl_level, float(alert.rule_level))

            if bl_level.n >= _MIN_N and z_level >= _ZSCORE_HIGH:
                anomaly = UebaAnomaly(
                    alert_id=alert.id,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    metric="rule_level",
                    observed_value=float(alert.rule_level),
                    baseline_mean=bl_level.mean,
                    baseline_stddev=stddev(bl_level),
                    z_score=z_level,
                    severity=_severity_from_zscore(z_level),
                    details={
                        "rule_description": alert.rule_description,
                        "mitre_tactic": alert.mitre_tactic,
                    },
                )
                session.add(anomaly)
                anomalies.append(anomaly)

    return anomalies
