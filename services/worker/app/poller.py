import asyncio
import json
import logging
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from shared.config import settings
from shared.models.alert import Alert
from shared.connectors.wazuh_indexer import WazuhIndexerConnector

logger = logging.getLogger(__name__)


class AlertPoller:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client: redis.Redis | None = None

    async def start(self):
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("Alert poller started. Interval: %ds", settings.poll_interval_seconds)

        while True:
            try:
                await self.poll()
            except Exception as e:
                logger.error("Poll cycle failed: %s", e, exc_info=True)
            await asyncio.sleep(settings.poll_interval_seconds)

    async def poll(self):
        logger.info("Polling Wazuh Indexer for new alerts...")

        connector = WazuhIndexerConnector()
        raw_alerts = await connector.search_alerts(
            lookback_hours=settings.alert_lookback_hours,
            size=settings.max_alerts_per_poll,
        )

        if not raw_alerts:
            logger.info("No new alerts found")
            return

        logger.info("Found %d raw alerts", len(raw_alerts))

        async with self.session_factory() as session:
            new_count = 0
            for raw in raw_alerts:
                try:
                    alert = await self._normalize_alert(session, raw)
                    if alert:
                        session.add(alert)
                        await session.flush()
                        await self.redis_client.lpush(
                            "triage_queue",
                            json.dumps({"alert_id": str(alert.id), "timestamp": datetime.now(timezone.utc).isoformat()}),
                        )
                        new_count += 1
                except Exception as e:
                    logger.warning("Failed to process alert: %s", e)
                    continue

            await session.commit()
            logger.info("Ingested %d new alerts, queued for triage", new_count)

    async def _normalize_alert(self, session: AsyncSession, raw: dict) -> Alert | None:
        wazuh_alert_id = raw.get("id") or raw.get("_id")
        if not wazuh_alert_id:
            return None

        from sqlalchemy import select
        existing = await session.execute(
            select(Alert).where(Alert.wazuh_alert_id == wazuh_alert_id)
        )
        if existing.scalar_one_or_none():
            return None

        rule = raw.get("rule", {})
        agent = raw.get("agent", {})
        data = raw.get("data", {})
        src_ip = raw.get("srcip") or data.get("srcip")
        dst_ip = raw.get("dstip") or data.get("dstip")

        alert = Alert(
            wazuh_alert_id=str(wazuh_alert_id),
            rule_id=rule.get("id"),
            rule_description=rule.get("description"),
            rule_level=rule.get("level"),
            rule_groups=rule.get("groups", []),
            rule_firedtimes=rule.get("firedtimes"),
            mitre_tactic=rule.get("mitre", {}).get("tactic"),
            mitre_technique=rule.get("mitre", {}).get("technique"),
            agent_id=str(agent.get("id")) if agent.get("id") else None,
            agent_name=agent.get("name"),
            agent_ip=agent.get("ip"),
            source_ip=src_ip,
            destination_ip=dst_ip,
            user_name=data.get("user"),
            process_name=data.get("process") or data.get("win", {}).get("event", {}).get("processName"),
            file_name=data.get("file") or data.get("win", {}).get("event", {}).get("fileName"),
            file_hash=data.get("hash") or data.get("win", {}).get("event", {}).get("hash"),
            event_id=raw.get("id"),
            alert_timestamp=self._parse_timestamp(raw.get("timestamp")),
            raw_alert_redacted=self._redact_alert(raw),
        )
        return alert

    @staticmethod
    def _parse_timestamp(ts) -> datetime | None:
        if ts is None:
            return None
        if isinstance(ts, datetime):
            return ts
        try:
            return dateutil_parser.parse(str(ts))
        except Exception:
            return None

    def _redact_alert(self, raw: dict) -> dict:
        redacted = json.loads(json.dumps(raw))
        if "agent" in redacted and "key" in redacted.get("agent", {}):
            redacted["agent"]["key"] = "[REDACTED]"
        return redacted

    async def stop(self):
        if self.redis_client:
            await self.redis_client.close()
        await self.engine.dispose()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    poller = AlertPoller()
    try:
        await poller.start()
    except KeyboardInterrupt:
        await poller.stop()


if __name__ == "__main__":
    asyncio.run(main())
