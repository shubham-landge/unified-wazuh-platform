"""Prometheus metric writers for the triage worker.

These helpers write cumulative counter and histogram sample values to Redis
keys that the API metrics endpoint (services/api/app/routers/metrics.py)
reads and feeds to prometheus_client on every /metrics scrape.

The API side computes deltas for counters and observes histogram samples
from the lists, so the worker side only needs to increment counters and
push raw latency values.
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

# Cap the latency sample list to avoid unbounded Redis memory growth.
# LTRIM keeps the newest 1000 entries; older samples are discarded.
_MAX_LATENCY_SAMPLES = 1000


async def record_triage_success(redis_client: object) -> None:
    """Increment the cumulative triage success counter in Redis.

    Corresponds to ``soc_triage_success_total`` on the API scrape side.
    """
    try:
        await redis_client.incr("triage_success_total")  # type: ignore[union-attr]
    except Exception:
        logger.debug("Failed to record triage_success_total", exc_info=True)


async def record_triage_fail(redis_client: object) -> None:
    """Increment the cumulative triage failure counter in Redis.

    Corresponds to ``soc_triage_fail_total`` on the API scrape side.
    """
    try:
        await redis_client.incr("triage_fail_total")  # type: ignore[union-attr]
    except Exception:
        logger.debug("Failed to record triage_fail_total", exc_info=True)


async def record_triage_latency(redis_client: object, latency_ms: float) -> None:
    """Push a triage latency sample (ms) to the Redis sample list.

    The list is trimmed to _MAX_LATENCY_SAMPLES entries so it never grows
    unboundedly.  Oldest entries are discarded first (right-side LTRIM).

    Corresponds to ``soc_triage_latency_ms`` histogram on the API scrape side.
    """
    if latency_ms is None:
        return
    try:
        await redis_client.lpush("triage_latency_samples", str(latency_ms))  # type: ignore[union-attr]
        await redis_client.ltrim(  # type: ignore[union-attr]
            "triage_latency_samples", 0, _MAX_LATENCY_SAMPLES - 1,
        )
    except Exception:
        logger.debug("Failed to record triage latency sample", exc_info=True)


async def push_to_dlq(redis_client: object, alert_id: str, error: str) -> None:
    """Push a failed triage job onto the dead-letter queue.

    The API metrics endpoint reads ``LLEN triage_dlq`` to populate the
    ``soc_dlq_depth`` gauge.
    """
    try:
        payload = json.dumps({"alert_id": alert_id, "error": error})
        await redis_client.lpush("triage_dlq", payload)  # type: ignore[union-attr]
    except Exception:
        logger.debug("Failed to push alert %s to DLQ", alert_id, exc_info=True)
