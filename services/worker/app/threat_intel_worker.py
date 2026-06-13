import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings
from shared.models.alert import Alert
from shared.models.threat_intel import ThreatIntelIoc, AlertIocMatch
from shared.connectors.ti_alienvault import AlienVaultOTXConnector
from shared.connectors.ti_misp import MISPConnector
from shared.connectors.ti_virustotal import VirusTotalConnector

logger = logging.getLogger(__name__)

TI_ENRICH_QUEUE = "ti_enrich_queue"
TI_ENRICH_DLQ = "ti_enrich_dlq"

# IOC fields to extract from an alert and their type
_ALERT_IOC_FIELDS = [
    ("source_ip",      "ip"),
    ("destination_ip", "ip"),
    ("file_hash",      "hash_sha256"),
    ("user_name",      "email"),   # may be email format
]

# Cache TTL for negative (not found) lookups — avoids hammering APIs
_NEGATIVE_TTL_HOURS = 6
_POSITIVE_TTL_HOURS = 24


class ThreatIntelWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client: redis.Redis | None = None
        self.otx = AlienVaultOTXConnector()
        self.misp = MISPConnector()
        self.vt = VirusTotalConnector()

    async def start(self):
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("Threat intel worker started")

        # Run feed polling and alert enrichment concurrently
        await asyncio.gather(
            self._enrichment_loop(),
            self._feed_poll_loop(),
        )

    async def _enrichment_loop(self):
        while True:
            try:
                item = await self.redis_client.brpop(TI_ENRICH_QUEUE, timeout=5)
                if item:
                    _, raw = item
                    await self._enrich_alert(json.loads(raw))
            except TypeError:
                continue
            except Exception as e:
                logger.error("TI enrichment error: %s", e, exc_info=True)
                await asyncio.sleep(1)

    async def _feed_poll_loop(self):
        """Poll TI feeds periodically and upsert IOCs into the DB."""
        poll_interval = getattr(settings, "ti_feed_poll_interval_seconds", 3600)
        while True:
            await asyncio.sleep(poll_interval)
            try:
                await self._poll_feeds()
            except Exception as e:
                logger.error("TI feed poll failed: %s", e, exc_info=True)

    async def _poll_feeds(self):
        logger.info("Polling TI feeds...")

        # OTX subscribed pulses
        pulses = await self.otx.get_subscribed_pulses(limit=200)
        iocs_to_upsert = []
        for pulse in pulses:
            for indicator in pulse.get("indicators", []):
                iocs_to_upsert.append({
                    "ioc_type": self._normalize_otx_type(indicator.get("type", "")),
                    "ioc_value": indicator.get("indicator", ""),
                    "source": "otx",
                    "threat_score": None,
                    "confidence": 0.6,
                    "malware_families": pulse.get("malware_families", []),
                    "tags": pulse.get("tags", []),
                    "raw_data": {"pulse_id": pulse.get("id"), "pulse_name": pulse.get("name")},
                })

        # MISP recent events
        events = await self.misp.get_recent_events(days=1, limit=100)
        for event in events:
            for attr in event.get("Event", {}).get("Attribute", []):
                ioc_type = self._normalize_misp_type(attr.get("type", ""))
                if ioc_type:
                    iocs_to_upsert.append({
                        "ioc_type": ioc_type,
                        "ioc_value": attr.get("value", ""),
                        "source": "misp",
                        "threat_score": None,
                        "confidence": 0.7,
                        "malware_families": [],
                        "tags": [t["name"] for t in attr.get("Tag", [])],
                        "raw_data": {"event_id": event.get("Event", {}).get("id")},
                    })

        if iocs_to_upsert:
            await self._upsert_iocs(iocs_to_upsert)
            logger.info("TI feed poll: upserted %d IOCs", len(iocs_to_upsert))

    async def _upsert_iocs(self, iocs: list[dict]):
        async with self.session_factory() as session:
            for ioc_data in iocs:
                if not ioc_data["ioc_value"] or not ioc_data["ioc_type"]:
                    continue
                existing = await session.execute(
                    select(ThreatIntelIoc).where(
                        ThreatIntelIoc.source == ioc_data["source"],
                        ThreatIntelIoc.ioc_value == ioc_data["ioc_value"],
                    )
                )
                obj = existing.scalar_one_or_none()
                if obj:
                    obj.updated_at = datetime.now(timezone.utc)
                    obj.last_seen = datetime.now(timezone.utc)
                    if ioc_data.get("tags"):
                        obj.tags = ioc_data["tags"]
                else:
                    obj = ThreatIntelIoc(
                        ioc_type=ioc_data["ioc_type"],
                        ioc_value=ioc_data["ioc_value"],
                        source=ioc_data["source"],
                        threat_score=ioc_data.get("threat_score"),
                        confidence=ioc_data.get("confidence"),
                        malware_families=ioc_data.get("malware_families"),
                        tags=ioc_data.get("tags"),
                        raw_data=ioc_data.get("raw_data"),
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                    )
                    session.add(obj)
            await session.commit()

    async def _enrich_alert(self, msg: dict):
        alert_id = msg.get("alert_id")
        if not alert_id:
            return

        try:
            async with self.session_factory() as session:
                result = await session.execute(select(Alert).where(Alert.id == alert_id))
                alert = result.scalar_one_or_none()
                if not alert:
                    return

                matches = []
                for field, ioc_type in _ALERT_IOC_FIELDS:
                    value = getattr(alert, field, None)
                    if not value:
                        continue
                    # Skip obviously non-threatening values
                    if ioc_type == "ip" and (value.startswith("10.") or value.startswith("192.168.") or value.startswith("172.")):
                        continue
                    if ioc_type == "email" and "@" not in value:
                        continue

                    cache_key = f"ti_cache:{ioc_type}:{value}"
                    cached = await self.redis_client.get(cache_key)
                    if cached:
                        results_list = [json.loads(cached)]
                    else:
                        results_list = await asyncio.gather(
                            self.otx.lookup(ioc_type, value),
                            self.misp.search(ioc_type, value),
                            self.vt.lookup(ioc_type, value),
                            return_exceptions=True,
                        )
                        # Cache the best result
                        best = next((r for r in results_list if isinstance(r, dict) and r.get("found")), None)
                        ttl = _POSITIVE_TTL_HOURS * 3600 if best else _NEGATIVE_TTL_HOURS * 3600
                        await self.redis_client.setex(cache_key, ttl, json.dumps(best or {"found": False}))

                    for ti_result in results_list:
                        if isinstance(ti_result, dict) and ti_result.get("found"):
                            # Upsert IOC record
                            await self._upsert_iocs([ti_result])
                            # Find the IOC record to get its ID
                            ioc_rec = await session.execute(
                                select(ThreatIntelIoc).where(
                                    ThreatIntelIoc.source == ti_result["source"],
                                    ThreatIntelIoc.ioc_value == value,
                                )
                            )
                            ioc_obj = ioc_rec.scalar_one_or_none()
                            if ioc_obj:
                                matches.append(AlertIocMatch(
                                    alert_id=alert.id,
                                    ioc_id=ioc_obj.id,
                                    matched_field=field,
                                    matched_value=value,
                                    threat_score=ti_result.get("threat_score"),
                                ))

                if matches:
                    for m in matches:
                        session.add(m)
                    await session.commit()
                    logger.info("TI enrichment: %d IOC matches for alert %s", len(matches), alert_id)
                else:
                    logger.debug("TI enrichment: no matches for alert %s", alert_id)

        except Exception as e:
            logger.error("TI enrichment failed for alert %s: %s", alert_id, e, exc_info=True)
            if self.redis_client:
                await self.redis_client.lpush(TI_ENRICH_DLQ, json.dumps({"alert_id": str(alert_id), "error": str(e)}))

    @staticmethod
    def _normalize_otx_type(otx_type: str) -> str:
        mapping = {
            "IPv4": "ip", "IPv6": "ip",
            "domain": "domain", "hostname": "domain",
            "URL": "url",
            "FileHash-MD5": "hash_md5",
            "FileHash-SHA256": "hash_sha256",
            "FileHash-SHA1": "hash_sha1",
            "email": "email",
        }
        return mapping.get(otx_type, "")

    @staticmethod
    def _normalize_misp_type(misp_type: str) -> str:
        mapping = {
            "ip-src": "ip", "ip-dst": "ip",
            "domain": "domain", "hostname": "domain",
            "url": "url",
            "md5": "hash_md5",
            "sha256": "hash_sha256",
            "sha1": "hash_sha1",
            "email-src": "email", "email-dst": "email",
        }
        return mapping.get(misp_type, "")

    async def stop(self):
        if self.redis_client:
            await self.redis_client.close()
        await self.engine.dispose()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = ThreatIntelWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
