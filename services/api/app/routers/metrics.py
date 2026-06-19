import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.middleware.auth import validate_api_key
from shared.config import settings
from shared.models.alert import Alert
from shared.models.case import Case

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/metrics", tags=["metrics"])

# Dedicated registry so we don't pollute the global default registry.
REGISTRY = CollectorRegistry()

ALERT_VOLUME_24H = Gauge(
    "soc_alert_volume_24h",
    "Number of alerts ingested in the last 24 hours",
    registry=REGISTRY,
)
OPEN_CASES = Gauge(
    "soc_open_cases_total",
    "Total number of open cases",
    registry=REGISTRY,
)
MTTR_SECONDS = Gauge(
    "soc_mttr_seconds",
    "Mean time to resolve (seconds) for closed cases",
    registry=REGISTRY,
)
MTTD_SECONDS = Gauge(
    "soc_mttd_seconds",
    "Mean time to detect (seconds) for alerts in the last 24 hours",
    registry=REGISTRY,
)
AGENT_QUEUE_DEPTH = Gauge(
    "soc_agent_queue_depth",
    "Current depth of the agent worker Redis queue",
    registry=REGISTRY,
)

# Noise-gate / triage-tier counters (set from Redis keys written by triage_worker)
TRIAGE_SUPPRESSED = Gauge("soc_triage_suppressed_total", "Total triage decisions suppressed by noise gate", registry=REGISTRY)
TRIAGE_KEPT = Gauge("soc_triage_kept_total", "Total triage decisions kept by noise gate", registry=REGISTRY)
TRIAGE_TIER_FAST = Gauge("soc_triage_tier_fast_total", "Total triage calls routed to fast tier", registry=REGISTRY)
TRIAGE_TIER_FULL = Gauge("soc_triage_tier_full_total", "Total triage calls routed to full tier", registry=REGISTRY)

INCIDENT_MTTD = Gauge("soc_incident_mttd_seconds", "Incident mean time to detect in seconds", registry=REGISTRY)
INCIDENT_MTTR = Gauge("soc_incident_mttr_seconds", "Incident mean time to resolve in seconds", registry=REGISTRY)
TIME_TO_FULL_ENRICHMENT = Gauge("soc_time_to_full_enrichment_seconds", "Mean time to full enrichment in seconds", registry=REGISTRY)
BREAKOUT_INCIDENTS = Gauge("soc_breakout_incidents_total", "Total breakout incidents", registry=REGISTRY)

# ── SLO metrics ──────────────────────────────────────────────────────────────
TRIAGE_SUCCESS_TOTAL = Counter(
    "soc_triage_success_total",
    "Cumulative count of successful triage decisions (delta from last scrape)",
    registry=REGISTRY,
)
TRIAGE_FAIL_TOTAL = Counter(
    "soc_triage_fail_total",
    "Cumulative count of failed triage decisions (delta from last scrape)",
    registry=REGISTRY,
)
DLQ_DEPTH = Gauge(
    "soc_dlq_depth",
    "Current depth of the triage dead-letter queue",
    registry=REGISTRY,
)
TRIAGE_LATENCY_MS = Histogram(
    "soc_triage_latency_ms",
    "Triage latency in milliseconds (sampled per scrape)",
    buckets=[50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000],
    registry=REGISTRY,
)



def _try_redis_queue_depth() -> int | None:
    try:
        import redis

        r = redis.from_url(settings.redis_url, decode_responses=True)
        depth = r.llen("agent_queue")
        r.close()
        return depth
    except Exception as exc:
        logger.debug("Could not fetch agent queue depth: %s", exc)
        return None


@router.get("")
async def metrics(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    # Alert volume (last 24h)
    alert_count_result = await db.execute(
        select(func.count(Alert.id)).where(Alert.created_at >= day_ago)
    )
    ALERT_VOLUME_24H.set(alert_count_result.scalar() or 0)

    # Open cases
    open_cases_result = await db.execute(
        select(func.count(Case.id)).where(Case.status != "closed")
    )
    OPEN_CASES.set(open_cases_result.scalar() or 0)

    # MTTR for closed cases
    mttr_result = await db.execute(
        select(
            func.avg(
                func.extract("epoch", Case.closed_at) - func.extract("epoch", Case.created_at)
            )
        ).where(Case.status == "closed", Case.closed_at.isnot(None))
    )
    mttr_value = mttr_result.scalar()
    MTTR_SECONDS.set(mttr_value if mttr_value is not None else 0)

    # MTTD for recent alerts (ingested_at - created_at of the alert/event)
    mttd_result = await db.execute(
        select(
            func.avg(
                func.extract("epoch", Alert.ingested_at) - func.extract("epoch", Alert.created_at)
            )
        ).where(Alert.ingested_at.isnot(None), Alert.created_at >= day_ago)
    )
    mttd_value = mttd_result.scalar()
    MTTD_SECONDS.set(mttd_value if mttd_value is not None else 0)

    # Agent queue depth
    depth = _try_redis_queue_depth()
    if depth is not None:
        AGENT_QUEUE_DEPTH.set(depth)

    # Triage noise-gate counters — read from Redis keys written by triage_worker
    try:
        import redis as _redis
        r = _redis.from_url(settings.redis_url, decode_responses=True)
        TRIAGE_SUPPRESSED.set(float(r.get("triage_suppressed_total") or 0))
        TRIAGE_KEPT.set(float(r.get("triage_kept_total") or 0))
        TRIAGE_TIER_FAST.set(float(r.get("triage_tier_fast_total") or 0))
        TRIAGE_TIER_FULL.set(float(r.get("triage_tier_full_total") or 0))
        
        breakout = r.get("breakout_incidents_total") or 0
        mttd = r.get("incident_mttd_seconds") or 0
        mttr = r.get("incident_mttr_seconds") or 0
        enrichment = r.get("time_to_full_enrichment_seconds") or 0
        
        INCIDENT_MTTD.set(float(mttd))
        INCIDENT_MTTR.set(float(mttr))
        TIME_TO_FULL_ENRICHMENT.set(float(enrichment))
        BREAKOUT_INCIDENTS.set(float(breakout))

        # ── SLO metrics ──────────────────────────────────────────────────
        # Delta counters: compute delta since last scrape, inc Counter by delta.
        success_total_raw = r.get("triage_success_total")
        fail_total_raw = r.get("triage_fail_total")
        if success_total_raw is not None:
            current = int(success_total_raw)
            last = int(r.get("slo_last_seen_triage_success") or 0)
            delta = max(0, current - last)
            if delta > 0:
                TRIAGE_SUCCESS_TOTAL.inc(delta)
            r.set("slo_last_seen_triage_success", str(current))
        if fail_total_raw is not None:
            current = int(fail_total_raw)
            last = int(r.get("slo_last_seen_triage_fail") or 0)
            delta = max(0, current - last)
            if delta > 0:
                TRIAGE_FAIL_TOTAL.inc(delta)
            r.set("slo_last_seen_triage_fail", str(current))

        # DLQ depth gauge
        dlq_raw = r.llen("triage_dlq") or 0
        DLQ_DEPTH.set(int(dlq_raw))

        # Latency histogram: sample recent latencies from Redis list
        latency_samples = r.lrange("triage_latency_samples", 0, -1)
        if latency_samples:
            for val in latency_samples:
                try:
                    TRIAGE_LATENCY_MS.observe(float(val))
                except (ValueError, TypeError):
                    pass

        r.close()
    except Exception as exc:
        logger.debug("Failed to read triage metrics from Redis: %s", exc)

    data = generate_latest(REGISTRY)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
