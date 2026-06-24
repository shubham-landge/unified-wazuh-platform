"""Playbook Worker.

Consumes the ``playbook_queue`` Redis list, evaluates trigger conditions against
the alert/case payload, and executes matching playbook actions via the SOAR
engine.

This replaces the "fake JSON store" approach used by the dashboard prototype.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shared.config import settings
from shared.models.playbook import Playbook, PlaybookRun
from shared.soar.engine import SoarEngine

logger = logging.getLogger(__name__)


class PlaybookWorker:
    """Redis-list consumer: matches alert/case messages to playbooks and runs them."""

    def __init__(self, session_factory=None, redis_client=None):
        self.engine = None
        if session_factory is None:
            self.engine = create_async_engine(settings.database_url, pool_size=2)
            self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        else:
            self.session_factory = session_factory
        self.redis_client = redis_client
        self.soar = SoarEngine()

    async def start(self):
        if self.redis_client is None:
            self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("Playbook worker started. Waiting for playbook_queue messages ...")

        while True:
            try:
                item = await self.redis_client.brpop("playbook_queue", timeout=5)
                if item:
                    _, msg = item
                    await self._process_message(json.loads(msg))
            except TypeError:
                continue
            except Exception as exc:
                logger.error("Playbook worker error: %s", exc, exc_info=True)
                await asyncio.sleep(1)

    async def stop(self):
        if self.redis_client:
            await self.redis_client.close()
        if self.engine:
            await self.engine.dispose()

    # ── Internal ────────────────────────────────────────────────────────────

    async def _process_message(self, payload: dict) -> None:
        """Evaluate playbooks and execute matching ones."""
        alert_id = payload.get("alert_id")
        case_id = payload.get("case_id")
        context = payload.get("context", {})
        tenant_id = payload.get("tenant_id")

        async with self.session_factory() as session:
            # Load active playbooks ordered by priority.
            result = await session.execute(
                select(Playbook)
                .where(Playbook.is_active.is_(True))
                .order_by(Playbook.priority)
            )
            active_playbooks = result.scalars().all()

            for pb in active_playbooks:
                if not self._matches_trigger(pb.trigger, context):
                    continue

                logger.info(
                    "Playbook '%s' triggered for alert=%s case=%s",
                    pb.name, alert_id, case_id,
                )

                run = PlaybookRun(
                    playbook_id=pb.id,
                    alert_id=alert_id,
                    case_id=case_id,
                    status="running",
                    actions_completed=0,
                    actions_total=len(pb.actions),
                    started_at=datetime.now(timezone.utc),
                )
                session.add(run)
                await session.flush()  # get run.id

                try:
                    result_data = await self.soar.execute_playbook(
                        playbook_id=str(pb.id),
                        actions=pb.actions,
                        context=context,
                        session=session,
                    )
                    run.status = "completed"
                    run.actions_completed = len(pb.actions)
                    run.result = result_data
                except Exception as exc:
                    logger.exception("Playbook '%s' failed: %s", pb.name, exc)
                    run.status = "failed"
                    run.error = str(exc)

                run.completed_at = datetime.now(timezone.utc)
                await session.commit()

        logger.info("Processed playbook_queue message: alert=%s case=%s", alert_id, case_id)

    @staticmethod
    def _matches_trigger(trigger: dict, context: dict) -> bool:
        """Evaluate a trigger condition dict against the alert/case context.

        Supports simple field checks and a minimal ``and``/``or`` combinator.
        Example trigger::

            {"field": "rule_level", "op": "gte", "value": 12}

        Returns ``True`` when the trigger matches or when the trigger is empty.
        """
        if not trigger:
            return True

        # Combinators
        and_conds = trigger.get("and")
        if isinstance(and_conds, list):
            return all(PlaybookWorker._matches_trigger(c, context) for c in and_conds)

        or_conds = trigger.get("or")
        if isinstance(or_conds, list):
            return any(PlaybookWorker._matches_trigger(c, context) for c in or_conds)

        field = trigger.get("field")
        op = trigger.get("op", "eq")
        expected = trigger.get("value")

        actual = context.get(field) if field else None
        if actual is None:
            return False

        try:
            if op == "eq":
                return actual == expected
            elif op == "neq":
                return actual != expected
            elif op == "gt":
                return float(actual) > float(expected)
            elif op == "gte":
                return float(actual) >= float(expected)
            elif op == "lt":
                return float(actual) < float(expected)
            elif op == "lte":
                return float(actual) <= float(expected)
            elif op == "in":
                return actual in (expected if isinstance(expected, list) else [expected])
            elif op == "contains":
                return str(expected) in str(actual)
            else:
                logger.warning("Unknown trigger op '%s' in %s", op, trigger)
                return False
        except (TypeError, ValueError) as exc:
            logger.debug("Trigger eval error: %s", exc)
            return False


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = PlaybookWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
