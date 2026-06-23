"""Trigger worker -- cron scheduler + webhook receiver -> spawns AgentRuns.

Reads trigger configuration from settings.triggers_cron and settings.triggers_webhooks.
Each fired trigger creates an AgentRun record and pushes it to the agent_queue
so the orchestration engine (AgentWorker) picks it up.

Cron format:  "cron_expr;agent_type;description"  (comma-separated entries)
Webhook format: "path_secret;agent_type;description"  (comma-separated entries)

Start via: python -m services.worker.app.trigger_worker
Or included in worker main.py task list.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shared.config import settings
from shared.models.agent import AgentDefinition, AgentRun

logger = logging.getLogger(__name__)


# -- Cron field pattern -------------------------------------------------------
# A cron field starts with a digit or asterisk; commas only appear *within*
# a field (e.g. "1,15,30,45"), never as the first character.
_CRON_FIELD = r"[\d\*][\d\*,/\-]*"
_CRON_EXPR = rf"{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}"


# -- Minimal cron parser (no external deps) ----------------------------------

def _cron_matches(cron_expr: str, dt: datetime) -> bool:
    """Return True if the given datetime matches a 5-field cron expression.

    Supports: *, comma-separated values, ranges (5-10), and step values (*/5).
    """
    try:
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return False
        minute, hour, dom, month, dow = parts

        def _match(field: str, value: int) -> bool:
            if field == "*":
                return True
            # Step values: */N or 1-30/5
            if "/" in field:
                base, step = field.split("/", 1)
                step_val = int(step)
                if base == "*":
                    return value % step_val == 0
                # Range with step: m-n/step
                if "-" in base:
                    lo_s, hi_s = base.split("-", 1)
                    lo, hi = int(lo_s), int(hi_s)
                    if lo <= value <= hi:
                        return (value - lo) % step_val == 0
                    return False
                return False
            # Comma-separated values
            if "," in field:
                candidates = []
                for part in field.split(","):
                    part = part.strip()
                    if "-" in part:
                        lo_s, hi_s = part.split("-", 1)
                        candidates.extend(range(int(lo_s), int(hi_s) + 1))
                    else:
                        candidates.append(int(part.strip()))
                return value in candidates
            # Single value or range
            if "-" in field:
                lo_s, hi_s = field.split("-", 1)
                return int(lo_s) <= value <= int(hi_s)
            return value == int(field)

        return (
            _match(minute, dt.minute)
            and _match(hour, dt.hour)
            and _match(dom, dt.day)
            and _match(month, dt.month)
            and _match(dow, dt.weekday())  # 0=Monday
        )
    except Exception:
        return False


# -- Trigger definitions -----------------------------------------------------

@dataclass
class CronTrigger:
    cron_expr: str
    agent_type: str
    description: str


@dataclass
class WebhookTrigger:
    path_secret: str
    agent_type: str
    description: str


def _parse_cron_triggers(raw: str) -> list[CronTrigger]:
    """Parse cron trigger config. Handles commas inside cron fields.

    Entries are comma-separated. Each entry is:
      5-field-cron-expr;agent_type[;description]

    Cron fields may themselves contain commas (e.g. "1,15,30,45").
    Entries are identified by their unique structure: exactly 5 space-separated
    cron-field tokens, then ;agent_type.  The description must not contain commas
    (commas are reserved as entry delimiters).
    """
    triggers: list[CronTrigger] = []
    if not raw:
        return triggers

    # Each trigger entry: (5 cron fields) ; (agent_type) [; (description)]
    # Description is limited to non-comma chars so the entry boundary is unambiguous.
    entry_pat = re.compile(
        rf"({_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD})"
        rf"\s*;\s*(\w+)\s*(?:;\s*([^,]*))?",
    )
    for m in entry_pat.finditer(raw):
        triggers.append(CronTrigger(
            cron_expr=m.group(1).strip(),
            agent_type=m.group(2).strip(),
            description=m.group(3).strip() if m.group(3) else "",
        ))
    return triggers


def _parse_webhook_triggers(raw: str) -> list[WebhookTrigger]:
    """Parse webhook trigger config.

    Entries are comma-separated. Each entry is:
      path_secret;agent_type[;description]

    path_secret and description must not contain semicolons or commas.
    """
    triggers: list[WebhookTrigger] = []
    if not raw:
        return triggers

    entry_pat = re.compile(r"([^;,]+)\s*;\s*(\w+)\s*(?:;\s*([^,]*))?")
    for m in entry_pat.finditer(raw):
        triggers.append(WebhookTrigger(
            path_secret=m.group(1).strip(),
            agent_type=m.group(2).strip(),
            description=m.group(3).strip() if m.group(3) else "",
        ))
    return triggers


# -- AgentRun spawner --------------------------------------------------------

async def _get_or_create_definition(
    session: AsyncSession,
    agent_type: str,
    description: str,
    tenant_id: uuid.UUID,
) -> AgentDefinition:
    """Look up an AgentDefinition by agent_type, or create one if missing."""
    result = await session.execute(
        select(AgentDefinition).where(
            AgentDefinition.tenant_id == tenant_id,
            AgentDefinition.agent_type == agent_type,
            AgentDefinition.is_active == True,
        )
    )
    definition = result.scalar_one_or_none()
    if definition is not None:
        return definition

    # Create a default definition for this agent type
    definition = AgentDefinition(
        name=f"trigger-{agent_type}",
        description=description or f"Auto-created trigger agent: {agent_type}",
        agent_type=agent_type,
        config={"tasks": [{"agent_type": agent_type}]},
        autonomy_level="approval",
        is_active=True,
        tenant_id=tenant_id,
    )
    session.add(definition)
    await session.flush()
    logger.info("Created AgentDefinition %s for agent_type=%s", definition.id, agent_type)
    return definition


async def _spawn_agent_run(
    session: AsyncSession,
    agent_type: str,
    description: str,
    trigger_type: str,
    trigger_ref: str,
    tenant_id: uuid.UUID,
    redis_client: aioredis.Redis | None = None,
    input_data: dict | None = None,
) -> str:
    """Create an AgentRun record and enqueue it for the orchestration engine.

    Returns the run UUID string, or empty string on failure.
    """
    try:
        definition = await _get_or_create_definition(
            session, agent_type, description, tenant_id,
        )
        run = AgentRun(
            id=uuid.uuid4(),
            definition_id=definition.id,
            tenant_id=tenant_id,
            trigger_type=trigger_type,
            trigger_ref=trigger_ref,
            status="pending",
            result_summary=description or None,
        )
        session.add(run)
        await session.commit()

        # Push to agent_queue so AgentWorker picks it up
        if redis_client is not None:
            try:
                await redis_client.lpush(
                    "agent_queue",
                    json.dumps({"run_id": str(run.id)}),
                )
            except Exception as exc:
                logger.warning("Failed to enqueue AgentRun %s: %s", run.id, exc)

        logger.info(
            "Spawned AgentRun %s (type=%s, trigger=%s:%s)",
            run.id, agent_type, trigger_type, trigger_ref,
        )
        return str(run.id)
    except Exception as exc:
        logger.error("Failed to spawn AgentRun for %s: %s", agent_type, exc)
        return ""


# -- TriggerWorker -----------------------------------------------------------

class TriggerWorker:
    """Scheduled trigger engine: cron + webhook.

    - Cron: polls every 30s, fires matching triggers once per minute.
    - Webhook: receives inbound path_secret matches and spawns AgentRuns.
    """

    def __init__(self, session_factory: async_sessionmaker | None = None):
        self.settings = settings
        self._session_factory = session_factory
        self._engine = None  # lazy singleton
        self._redis_client: aioredis.Redis | None = None
        self._stopped = asyncio.Event()
        self._last_fired: dict[str, int] = {}  # trigger key -> last minute fired

    def _session(self):
        if self._session_factory:
            return self._session_factory()
        from sqlalchemy.ext.asyncio import create_async_engine

        if self._engine is None:
            self._engine = create_async_engine(settings.database_url, pool_size=2)
        return async_sessionmaker(self._engine, expire_on_commit=False)()

    async def _ensure_redis(self) -> aioredis.Redis:
        if self._redis_client is None:
            self._redis_client = await aioredis.from_url(
                settings.redis_url, decode_responses=True,
            )
        return self._redis_client

    async def _get_tenant_id(self) -> uuid.UUID:
        """Return the default tenant UUID.

        Looks for default_tenant_uuid helper; falls back to a zero UUID.
        """
        try:
            from shared.config import default_tenant_uuid  # type: ignore[import-untyped]
            return default_tenant_uuid()
        except Exception:
            return uuid.UUID("00000000-0000-0000-0000-000000000001")

    async def _fire_cron_triggers(self):
        """Check all cron triggers and fire those matching the current minute."""
        raw = self.settings.triggers_cron
        if not raw:
            return

        triggers = _parse_cron_triggers(raw)
        if not triggers:
            return

        now = datetime.now(timezone.utc)
        minute_key = int(now.strftime("%Y%m%d%H%M"))

        for t in triggers:
            key = f"{t.cron_expr}:{t.agent_type}"
            if self._last_fired.get(key) == minute_key:
                continue  # already fired this minute
            if _cron_matches(t.cron_expr, now):
                self._last_fired[key] = minute_key
                logger.info("Cron trigger fired: %s -> %s", t.cron_expr, t.agent_type)
                try:
                    tenant_id = await self._get_tenant_id()
                    redis_client = await self._ensure_redis()
                    async with self._session() as session:
                        await _spawn_agent_run(
                            session=session,
                            agent_type=t.agent_type,
                            description=t.description,
                            trigger_type="cron",
                            trigger_ref=t.cron_expr,
                            tenant_id=tenant_id,
                            redis_client=redis_client,
                        )
                except Exception as exc:
                    logger.error("Cron trigger %s failed: %s", key, exc)

    async def start(self):
        """Run the scheduler loop -- checks every 30 seconds."""
        logger.info("TriggerWorker started")
        while not self._stopped.is_set():
            try:
                await self._fire_cron_triggers()
            except Exception as exc:
                logger.error("TriggerWorker loop error: %s", exc)
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=30)
            except asyncio.TimeoutError:
                pass

    def stop(self):
        self._stopped.set()

    async def shutdown(self):
        """Gracefully close Redis and DB connections."""
        self._stopped.set()
        if self._redis_client is not None:
            await self._redis_client.close()
            self._redis_client = None
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None

    async def handle_webhook(
        self,
        path_secret: str,
        payload: dict,
        session: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> Optional[str]:
        """Handle an inbound webhook -- match path_secret and spawn AgentRun."""
        raw = self.settings.triggers_webhooks
        if not raw:
            return None
        for t in _parse_webhook_triggers(raw):
            if t.path_secret == path_secret:
                redis_client = await self._ensure_redis()
                return await _spawn_agent_run(
                    session=session,
                    agent_type=t.agent_type,
                    description=t.description,
                    trigger_type="webhook",
                    trigger_ref=path_secret,
                    tenant_id=tenant_id,
                    redis_client=redis_client,
                    input_data=payload,
                )
        return None


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    worker = TriggerWorker()
    try:
        asyncio.run(worker.start())
    except KeyboardInterrupt:
        asyncio.run(worker.shutdown())
