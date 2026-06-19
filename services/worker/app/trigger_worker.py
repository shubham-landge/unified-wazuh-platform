"""Trigger worker — cron scheduler + webhook receiver → spawns AgentRuns.

Reads trigger configuration from settings.triggers_cron and settings.triggers_webhooks.
Each fired trigger creates an AgentRun record that the orchestration engine picks up.

Cron format:  "cron_expr;agent_type;description"  (comma-separated entries)
Webhook format: "path_secret;agent_type;description"  (comma-separated entries)

Start via: python -m services.worker.app.trigger_worker
Or included in worker main.py task list.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ── Minimal cron parser (no external deps) ─────────────────────────────────

def _cron_matches(cron_expr: str, dt: datetime) -> bool:
    """Return True if the given datetime matches a 5-field cron expression.
    Supports: * and comma-separated values. No ranges/steps for simplicity.
    """
    try:
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return False
        minute, hour, dom, month, dow = parts

        def _match(field: str, value: int) -> bool:
            if field == "*":
                return True
            return value in [int(x) for x in field.split(",")]

        return (
            _match(minute, dt.minute)
            and _match(hour, dt.hour)
            and _match(dom, dt.day)
            and _match(month, dt.month)
            and _match(dow, dt.weekday())  # 0=Monday
        )
    except Exception:
        return False


# ── Trigger definitions ─────────────────────────────────────────────────────

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
    triggers = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(";", 2)
        if len(parts) >= 2:
            triggers.append(CronTrigger(
                cron_expr=parts[0].strip(),
                agent_type=parts[1].strip(),
                description=parts[2].strip() if len(parts) > 2 else "",
            ))
    return triggers


def _parse_webhook_triggers(raw: str) -> list[WebhookTrigger]:
    triggers = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(";", 2)
        if len(parts) >= 2:
            triggers.append(WebhookTrigger(
                path_secret=parts[0].strip(),
                agent_type=parts[1].strip(),
                description=parts[2].strip() if len(parts) > 2 else "",
            ))
    return triggers


# ── AgentRun spawner ────────────────────────────────────────────────────────

async def _spawn_agent_run(
    session,
    agent_type: str,
    description: str,
    trigger_source: str,
    tenant_id: uuid.UUID,
    input_data: Optional[dict] = None,
) -> str:
    """Insert an AgentRun record for the orchestration engine to pick up."""
    try:
        from shared.models.agent import AgentRun  # type: ignore
        run = AgentRun(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            agent_type=agent_type,
            status="queued",
            trigger_source=trigger_source,
            input_data=input_data if isinstance(input_data, str) else json.dumps(input_data or {}),
            description=description,
            created_at=datetime.now(timezone.utc),
        )
        session.add(run)
        await session.commit()
        logger.info("Spawned AgentRun %s (type=%s, trigger=%s)", run.id, agent_type, trigger_source)
        return run.id
    except Exception as exc:
        logger.error("Failed to spawn AgentRun for %s: %s", agent_type, exc)
        return ""


# ── Cron scheduler ──────────────────────────────────────────────────────────

class TriggerWorker:
    def __init__(self, session_factory=None):
        from shared.config import settings
        self.settings = settings
        self._session_factory = session_factory
        self._engine = None  # lazy singleton
        self._stopped = asyncio.Event()
        self._last_fired: dict[str, int] = {}  # trigger key → last minute fired

    def _session(self):
        if self._session_factory:
            return self._session_factory()
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
        from shared.config import settings
        if self._engine is None:
            self._engine = create_async_engine(settings.database_url, pool_size=2)
        return async_sessionmaker(self._engine, expire_on_commit=False)()

    async def _get_tenant_id(self) -> uuid.UUID:
        try:
            from shared.config import default_tenant_uuid
            return default_tenant_uuid()
        except Exception:
            return uuid.UUID("00000000-0000-0000-0000-000000000001")

    async def _fire_cron_triggers(self):
        """Check all cron triggers and fire those matching current minute."""
        raw = self.settings.triggers_cron
        if not raw:
            return

        triggers = _parse_cron_triggers(raw)
        now = datetime.now(timezone.utc)
        minute_key = now.strftime("%Y%m%d%H%M")

        for t in triggers:
            key = f"{t.cron_expr}:{t.agent_type}"
            if self._last_fired.get(key) == minute_key:
                continue  # already fired this minute
            if _cron_matches(t.cron_expr, now):
                self._last_fired[key] = minute_key
                logger.info("Cron trigger fired: %s → %s", t.cron_expr, t.agent_type)
                try:
                    tenant_id = await self._get_tenant_id()
                    async with self._session() as session:
                        await _spawn_agent_run(
                            session, t.agent_type, t.description,
                            f"cron:{t.cron_expr}", tenant_id,
                        )
                except Exception as exc:
                    logger.error("Cron trigger %s failed: %s", key, exc)

    async def start(self):
        """Run the scheduler loop — checks every 30 seconds."""
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

    async def handle_webhook(
        self,
        path_secret: str,
        payload: dict,
        session,
        tenant_id: uuid.UUID,
    ) -> Optional[str]:
        """Handle an inbound webhook — match path_secret and spawn AgentRun."""
        raw = self.settings.triggers_webhooks
        if not raw:
            return None
        for t in _parse_webhook_triggers(raw):
            if t.path_secret == path_secret:
                return await _spawn_agent_run(
                    session, t.agent_type, t.description,
                    f"webhook:{path_secret}", tenant_id, payload,
                )
        return None


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    worker = TriggerWorker()
    asyncio.run(worker.start())
