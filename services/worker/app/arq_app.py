"""ARQ durable queue for Antigravity workers.

Replaces the legacy Redis-list queue + DLQ with native arq durability:
  - max_tries / exponential backoff on retry
  - on_job_failure for permanent-failure parking
  - cron jobs for periodic health and reaper tasks

Job functions are module-level so they are importable and picklable by arq.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import redis.asyncio as aioredis
from arq.connections import RedisSettings
from arq.cron import cron
from sqlalchemy import update
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings

logger = logging.getLogger(__name__)


# ── Shared resources (lazy-initialized, reused across jobs) ────────────────

_redis_pool: aioredis.Redis | None = None
_db_engine = None


async def _get_redis() -> aioredis.Redis:
    """Return a shared Redis client with decode_responses=True."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = await aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
    return _redis_pool


def _get_engine():
    """Return a shared SQLAlchemy async engine."""
    global _db_engine
    if _db_engine is None:
        _db_engine = create_async_engine(settings.database_url, pool_size=2)
    return _db_engine


async def _close_shared():
    """Close engine and Redis pool. Idempotent."""
    global _redis_pool, _db_engine
    if _redis_pool is not None:
        await _redis_pool.close()
        _redis_pool = None
    if _db_engine is not None:
        await _db_engine.dispose()
        _db_engine = None


# ── Cron job functions (module-level for serialisability) ──────────────────

async def reaper_cron(ctx) -> None:
    """Fail pending triage rows older than the timeout window."""
    from shared.models.ai_triage_result import AiTriageResult

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=600)
    engine = _get_engine()
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as session:
        stmt = (
            update(AiTriageResult)
            .where(
                AiTriageResult.status == "pending",
                AiTriageResult.created_at < cutoff,
            )
            .values(
                status="failed",
                success=False,
                error_message="Reaper: triage timed out",
            )
        )
        result = await session.execute(stmt)
        await session.commit()
        if result.rowcount:
            logger.warning("Reaper failed %d stale pending triage row(s)", result.rowcount)


async def health_cron(ctx) -> None:
    """Log queue depth and worker health status."""
    redis_client = await _get_redis()
    triage_depth = await redis_client.llen("triage_queue")
    logger.info("Health: triage_queue=%d", triage_depth)


# ── Main job functions ─────────────────────────────────────────────────────

async def triage_job(ctx, alert_id: str, **kwargs: Any) -> dict[str, Any]:
    """ARQ job: triage a single alert via TriageWorker.process_message."""
    from services.worker.app.triage_worker import TriageWorker

    worker = TriageWorker()
    worker.engine = _get_engine()
    worker.session_factory = async_sessionmaker(worker.engine, expire_on_commit=False)
    worker.redis_client = await _get_redis()

    msg: dict[str, Any] = {"alert_id": alert_id, **kwargs}
    await worker.process_message(msg)
    return {"alert_id": alert_id, "status": "triage_completed"}


async def enrich_job(ctx, alert_id: str, **kwargs: Any) -> dict[str, Any]:
    """ARQ job: run the enrichment pipeline for an alert."""
    from sqlalchemy import select

    from shared.enrichment.pipeline import enrich_alert
    from shared.models.alert import Alert

    redis_client = await _get_redis()
    engine = _get_engine()
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as session:
        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            logger.warning("enrich_job: alert %s not found", alert_id)
            return {"alert_id": alert_id, "status": "alert_not_found"}

        ctx_data = await enrich_alert(alert, str(alert.tenant_id), session, redis_client)
        logger.info(
            "Enrichment for alert %s: ti_conf=%s vuln_matched=%s",
            alert_id,
            getattr(ctx_data, "ti_confidence", None),
            getattr(ctx_data, "vuln_matched", None),
        )

    return {"alert_id": alert_id, "status": "enrichment_completed"}


async def ti_enrich_job(ctx, alert_id: str, **kwargs: Any) -> dict[str, Any]:
    """ARQ job: run threat-intel IOC enrichment for an alert."""
    from services.worker.app.threat_intel_worker import ThreatIntelWorker

    worker = ThreatIntelWorker()
    worker.engine = _get_engine()
    worker.session_factory = async_sessionmaker(worker.engine, expire_on_commit=False)
    worker.redis_client = await _get_redis()

    await worker._enrich_alert({"alert_id": alert_id})
    return {"alert_id": alert_id, "status": "ti_enrich_completed"}


async def sigma_job(ctx, **kwargs: Any) -> dict[str, Any]:
    """ARQ job: run one Sigma rule scan cycle."""
    from services.worker.app.sigma_worker import SigmaWorker

    worker = SigmaWorker(
        session_factory=async_sessionmaker(_get_engine(), expire_on_commit=False),
    )
    result = await worker.scan_once()
    logger.info("Sigma scan result: %s", result)
    return {"status": "sigma_completed", **result}


# ── WorkerSettings (consumed by `arq.run.Worker` / CLI `arq app.WorkerSettings`) ──

class WorkerSettings:
    """Arq worker configuration for the Antigravity platform."""

    functions = [
        triage_job,
        enrich_job,
        ti_enrich_job,
        sigma_job,
    ]

    redis_settings = RedisSettings.from_dsn(settings.redis_url)

    max_tries = settings.arq_max_tries
    keep_result_seconds = settings.arq_keep_result_seconds

    cron_jobs = [
        cron(reaper_cron, second=0),       # every 60 seconds
        cron(health_cron, minute="*/2"),    # every 2 minutes
    ]

    @staticmethod
    async def on_startup(ctx) -> None:
        """Pre-warm shared Redis pool on worker boot."""
        logger.info("ARQ worker starting up ...")
        redis = await _get_redis()
        await redis.ping()
        logger.info("ARQ worker ready")

    @staticmethod
    async def on_shutdown(ctx) -> None:
        """Tear down shared resources gracefully."""
        logger.info("ARQ worker shutting down ...")
        await _close_shared()
