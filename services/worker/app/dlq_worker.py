"""Dead-letter queue consumer for triage jobs.

Drains the `triage_dlq` Redis list, re-enqueues failed jobs with bounded
retries and exponential backoff, and parks permanently failed jobs in
`triage_dlq_parked` so nothing is silently lost.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

import redis.asyncio as redis

from shared.config import settings

logger = logging.getLogger(__name__)

TRIAGE_QUEUE = "triage_queue"
TRIAGE_DLQ = "triage_dlq"
TRIAGE_DLQ_RETRIES = "triage_dlq_retries"
TRIAGE_DLQ_PARKED = "triage_dlq_parked"


class DLQWorker:
    def __init__(self):
        self.redis_client: redis.Redis | None = None
        self.max_retries = getattr(settings, "dlq_max_retries", 3)
        self.poll_interval = getattr(settings, "dlq_poll_interval", 5)
        self._shutdown = False

    async def start(self):
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info(
            "DLQ worker started. draining %s (max_retries=%d)",
            TRIAGE_DLQ,
            self.max_retries,
        )

        while not self._shutdown:
            try:
                item = await self.redis_client.brpop(TRIAGE_DLQ, timeout=self.poll_interval)
                if item:
                    _, raw = item
                    await self._handle(raw)
            except TypeError:
                # brpop timeout returns None when decode_responses=False, which
                # manifests as a TypeError on tuple unpack; continue the loop.
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("DLQ worker error: %s", e, exc_info=True)
                await asyncio.sleep(1)

    async def _handle(self, raw: str):
        job: dict = {}
        try:
            job = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("DLQ job is not valid JSON: %s", exc)
            # Move to parked so it is not retried indefinitely.
            await self._park({"raw": raw, "error": "invalid_json"})
            return

        alert_id = job.get("alert_id")
        error = job.get("error", "unknown")
        if not alert_id:
            logger.warning("DLQ job missing alert_id: %s", job)
            await self._park(job)
            return

        retry_count = await self._get_retry_count(alert_id)
        if retry_count >= self.max_retries:
            logger.warning(
                "DLQ parking alert %s after %d failed attempts: %s",
                alert_id,
                retry_count,
                error,
            )
            await self._park(job)
            return

        next_retry = retry_count + 1
        await self._set_retry_count(alert_id, next_retry)
        logger.info(
            "DLQ re-enqueue alert %s attempt %d/%d (previous error: %s)",
            alert_id,
            next_retry,
            self.max_retries,
            error,
        )

        # Exponential backoff: 2^retry seconds (2, 4, 8, ...).
        backoff = 2**next_retry
        await asyncio.sleep(backoff)

        # Re-enqueue without the DLQ fields so the triage worker treats it as
        # a normal job. Preserve any original fields like manual/force_fast.
        requeue = {k: v for k, v in job.items() if k not in ("error", "_error", "_dlq_at")}
        await self.redis_client.lpush(TRIAGE_QUEUE, json.dumps(requeue))

    async def _get_retry_count(self, alert_id: str) -> int:
        if not self.redis_client:
            return 0
        count = await self.redis_client.hget(TRIAGE_DLQ_RETRIES, str(alert_id))
        return int(count) if count else 0

    async def _set_retry_count(self, alert_id: str, count: int):
        if self.redis_client:
            await self.redis_client.hset(TRIAGE_DLQ_RETRIES, str(alert_id), count)

    async def _park(self, job: dict):
        if not self.redis_client:
            return
        parked = dict(job)
        parked["_parked_at"] = datetime.now(timezone.utc).isoformat()
        await self.redis_client.lpush(TRIAGE_DLQ_PARKED, json.dumps(parked))

    async def stop(self):
        self._shutdown = True
        if self.redis_client:
            await self.redis_client.close()


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    worker = DLQWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
