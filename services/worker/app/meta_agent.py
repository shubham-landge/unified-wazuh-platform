import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings, default_tenant_uuid
from shared.models.alert import Alert
from shared.models.ai_triage_result import AiTriageResult
from shared.models.agent import AgentDefinition, AgentRun, AgentTask
from shared.rag.skill_memory import add_experience

logger = logging.getLogger(__name__)

INDEXER_TIMEOUT = 30.0
REINDEX_TRIGGER_REDIS_KEY = "meta_agent:reindex_queue"
META_AGENT_NAME = "Meta Agent"


class MetaAgent:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self._stopped = asyncio.Event()
        self._meta_definition_id: uuid.UUID | None = None

    async def start(self):
        await self._resolve_definition_id()
        while not self._stopped.is_set():
            try:
                await self.scan_missed_detections()
            except Exception as e:
                logger.error("Meta agent missed-detection scan error: %s", e, exc_info=True)
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=86400)
            except asyncio.TimeoutError:
                pass

    async def stop(self):
        self._stopped.set()
        await self.engine.dispose()

    async def _resolve_definition_id(self):
        async with self.session_factory() as session:
            result = await session.execute(
                select(AgentDefinition).where(
                    AgentDefinition.name == META_AGENT_NAME,
                    AgentDefinition.is_active == True,
                )
            )
            defn = result.scalar_one_or_none()
            if not defn:
                # Self-heal: AgentTask.run_id is NOT NULL REFERENCES agent_runs,
                # so we must never invent a run_id. Create the definition if the
                # migration seed hasn't run, guaranteeing a valid run linkage.
                defn = AgentDefinition(
                    name=META_AGENT_NAME,
                    description="Nightly scan for missed detections (alerts with no triage).",
                    agent_type="meta_agent",
                    is_active=True,
                )
                session.add(defn)
                await session.flush()
                logger.info("Meta agent: seeded missing '%s' definition %s", META_AGENT_NAME, defn.id)
                await session.commit()
            self._meta_definition_id = defn.id
            logger.info("Meta agent: resolved definition ID %s", defn.id)

    async def scan_missed_detections(self):
        async with self.session_factory() as session:
            alerts_without_triage = await self._find_missed_alerts(session)
            if not alerts_without_triage:
                logger.info("Meta agent: no missed detections found")
                return

            categorized = self._categorize_missed(alerts_without_triage)
            logger.info(
                "Meta agent: %d missed detections (critical=%d, high=%d, medium=%d, low=%d)",
                len(alerts_without_triage),
                categorized.get("critical", 0),
                categorized.get("high", 0),
                categorized.get("medium", 0),
                categorized.get("low", 0),
            )

            indexer_missed = await self._query_indexer_for_missed(session)
            all_missed = alerts_without_triage + indexer_missed
            if not all_missed:
                return

            # A definition is always resolved at startup (self-healed if missing),
            # so we can create a real run and never orphan a task's run_id FK.
            run = AgentRun(
                definition_id=self._meta_definition_id,
                tenant_id=default_tenant_uuid(),
                trigger_type="scheduled",
                status="running",
                started_at=datetime.now(timezone.utc),
            )
            session.add(run)
            await session.flush()

            reindex_ids = []
            for alert in all_missed:
                task = AgentTask(
                    run_id=run.id,
                    agent_type="meta_agent",
                    input_data={
                        "alert_id": str(alert.id),
                        "rule_description": alert.rule_description,
                        "rule_level": alert.rule_level,
                        "rule_groups": list(alert.rule_groups) if alert.rule_groups else [],
                    },
                    output_data={
                        "triage_status": "missed_detection_ingested",
                        "rule_level": alert.rule_level,
                        "reindex": "pending",
                    },
                    status="completed",
                    started_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                )
                session.add(task)
                await session.flush()
                await add_experience(session, task)

                if alert.rule_level and alert.rule_level >= 10:
                    reindex_ids.append(str(alert.id))

            run.status = "completed"
            run.completed_at = datetime.now(timezone.utc)
            run.result_summary = f"Processed {len(all_missed)} missed detections ({len(reindex_ids)} high-severity flagged for re-triage)"

            await session.commit()

            if reindex_ids:
                await self._push_reindex_trigger(reindex_ids)
                logger.info("Meta agent: pushed %d high-severity alerts for re-triage", len(reindex_ids))

    async def _find_missed_alerts(self, session):
        stmt = (
            select(Alert)
            .outerjoin(AiTriageResult, Alert.id == AiTriageResult.alert_id)
            .where(AiTriageResult.id.is_(None))
            .order_by(Alert.created_at.desc())
            .limit(200)
        )
        res = await session.execute(stmt)
        return list(res.scalars().all())

    async def _query_indexer_for_missed(self, session):
        if not settings.wazuh_indexer_url:
            return []
        lookback = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        query = {
            "query": {
                "bool": {
                    "must": [{"range": {"@timestamp": {"gte": lookback}}}],
                    "must_not": [{"exists": {"field": "soc_triage_id"}}],
                }
            },
            "size": 100,
            "sort": [{"@timestamp": "desc"}],
        }
        auth = (
            settings.wazuh_indexer_user,
            settings.wazuh_indexer_password.get_secret_value(),
        )
        index = "wazuh-alerts-*"
        url = settings.wazuh_indexer_url.rstrip("/")
        try:
            async with httpx.AsyncClient(
                verify=settings.wazuh_indexer_verify_ssl,
                timeout=INDEXER_TIMEOUT,
                auth=auth,
            ) as client:
                response = await client.post(
                    f"{url}/{index}/_search",
                    json=query,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            logger.warning("Meta agent indexer query failed: %s", exc)
            return []

        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            return []

        existing_wazuh_ids = set()
        for hit in hits:
            source = hit.get("_source", {})
            wazuh_id = source.get("soc_alert_id") or source.get("id") or hit.get("_id")
            if wazuh_id:
                existing_wazuh_ids.add(str(wazuh_id))

        if not existing_wazuh_ids:
            return []

        existing = await session.execute(
            select(Alert.wazuh_alert_id).where(Alert.wazuh_alert_id.in_(existing_wazuh_ids))
        )
        known = {row[0] for row in existing.all()}

        fresh_hits = []
        for hit in hits:
            source = hit.get("_source", {})
            wazuh_id = str(source.get("soc_alert_id") or source.get("id") or hit.get("_id"))
            if wazuh_id not in known:
                fresh_hits.append(
                    Alert(
                        tenant_id=uuid.UUID(settings.tenant_id) if settings.tenant_id != "default" else uuid.UUID("00000000-0000-0000-0000-000000000001"),
                        wazuh_alert_id=wazuh_id,
                        rule_id=source.get("rule", {}).get("id"),
                        rule_description=source.get("rule", {}).get("description", "Missed detection from indexer"),
                        rule_level=int(source.get("rule", {}).get("level", 0)),
                        rule_groups=source.get("rule", {}).get("groups", []),
                        agent_id=source.get("agent", {}).get("id"),
                        agent_name=source.get("agent", {}).get("name"),
                        agent_ip=source.get("agent", {}).get("ip"),
                        source_ip=source.get("source", {}).get("ip"),
                        destination_ip=source.get("destination", {}).get("ip"),
                        user_name=source.get("user", {}).get("name"),
                        process_name=source.get("process", {}).get("name"),
                        event_type="indexer_recovery",
                        log_source="meta_agent",
                        raw_alert_redacted={"indexer_hit": source},
                        alert_timestamp=datetime.now(timezone.utc),
                    )
                )
        for alert in fresh_hits:
            session.add(alert)
        await session.flush()
        return fresh_hits

    def _categorize_missed(self, alerts):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for alert in alerts:
            level = alert.rule_level or 0
            if level >= 12:
                counts["critical"] += 1
            elif level >= 10:
                counts["high"] += 1
            elif level >= 7:
                counts["medium"] += 1
            else:
                counts["low"] += 1
        return counts

    async def _push_reindex_trigger(self, alert_ids: list[str]):
        try:
            import redis as _redis

            r = _redis.from_url(settings.redis_url, decode_responses=True)
            payload = json.dumps({"alert_ids": alert_ids, "triggered_by": "meta_agent"})
            r.rpush(REINDEX_TRIGGER_REDIS_KEY, payload)
            r.expire(REINDEX_TRIGGER_REDIS_KEY, 3600)
            r.close()
        except Exception as exc:
            logger.warning("Meta agent: failed to push reindex trigger: %s", exc)