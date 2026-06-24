"""Ingests vulnerabilities from Wazuh Indexer into the vulnerabilities table."""
import asyncio
import logging
import uuid
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings
from shared.connectors.wazuh_indexer import WazuhIndexerConnector
from shared.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
BATCH_SIZE = 200

SEVERITY_MAP = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "None": "none",
}


def _parse_cvss(doc: dict) -> float | None:
    vuln = doc.get("vulnerability", {})
    for key in ("cvss3_score", "cvss2_score"):
        val = vuln.get(key)
        if val is not None:
            try:
                return float(val)
            except (ValueError, TypeError):
                pass
    return None


def _parse_severity(doc: dict) -> str | None:
    vuln = doc.get("vulnerability", {})
    raw = vuln.get("severity", "medium")
    mapped = SEVERITY_MAP.get(raw)
    if mapped:
        return mapped
    return raw.lower() if raw else "medium"


def _parse_patch_available(doc: dict) -> bool | None:
    condition = doc.get("vulnerability", {}).get("package", {}).get("condition", "")
    if not condition:
        return None
    return "fixed" in condition.lower() or "not yet" not in condition.lower()


def _parse_cve_description(doc: dict) -> str | None:
    vuln = doc.get("vulnerability", {})
    title = vuln.get("title") or ""
    cwe = vuln.get("cwe") or ""
    description = vuln.get("description") or ""
    parts = [p for p in (title, cwe, description) if p]
    return parts[0] if parts else None


def _parse_timestamp(doc: dict, key: str) -> datetime:
    raw = doc.get(key) or doc.get("@timestamp")
    if raw:
        try:
            if isinstance(raw, str):
                raw = raw.replace("Z", "+00:00")
            return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc)


def _normalize(doc: dict) -> dict | None:
    vuln = doc.get("vulnerability", {})
    cve_id = vuln.get("cve") or ""
    if not cve_id:
        return None
    pkg = vuln.get("package", {}) or {}
    ts = _parse_timestamp(doc, "@timestamp")
    return {
        "cve_id": cve_id.upper(),
        "cvss_score": _parse_cvss(doc),
        "severity": _parse_severity(doc),
        "package_name": pkg.get("name"),
        "package_version": pkg.get("version"),
        "package_architecture": pkg.get("architecture"),
        "patch_available": _parse_patch_available(doc),
        "cve_description": _parse_cve_description(doc),
        "first_detected_at": ts,
        "last_detected_at": ts,
        "asset_id": None,
        "tenant_id": DEFAULT_TENANT_ID,
    }


class VulnIngester:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def start(self):
        logger.info(
            "Vulnerability ingester started. Interval: %dh",
            settings.vuln_poll_interval_hours,
        )
        await self.backfill()
        while True:
            await asyncio.sleep(settings.vuln_poll_interval_hours * 3600)
            await self.poll()

    async def backfill(self):
        indexers = settings.parsed_wazuh_indexers
        total = 0
        for idx_cfg in indexers:
            logger.info("Backfilling vulns from indexer: %s", idx_cfg.get("label", "default"))
            connector = WazuhIndexerConnector(
                base_url=idx_cfg["url"],
                user=idx_cfg["user"],
                password=idx_cfg["password"],
                label=idx_cfg.get("label", "default"),
            )
            docs = await self._fetch_all(connector)
            if docs:
                count = await self._store(docs)
                total += count
                logger.info("Backfill: %d new/updated from %s", count, idx_cfg.get("label", "default"))
            await connector.close()
        logger.info("Backfill complete: %d vulnerabilities total", total)

    async def poll(self):
        indexers = settings.parsed_wazuh_indexers
        for idx_cfg in indexers:
            connector = WazuhIndexerConnector(
                base_url=idx_cfg["url"],
                user=idx_cfg["user"],
                password=idx_cfg["password"],
                label=idx_cfg.get("label", "default"),
            )
            docs = await connector.search_vulnerabilities(size=BATCH_SIZE)
            if docs:
                count = await self._store(docs)
                logger.info("Poll: %d new/updated from %s", count, idx_cfg.get("label", "default"))
            await connector.close()

    async def _fetch_all(self, connector) -> list[dict]:
        all_docs = []
        offset = 0
        while True:
            docs = await connector.search_vulnerabilities(size=BATCH_SIZE, from_=offset)
            if not docs:
                break
            all_docs.extend(docs)
            if len(docs) < BATCH_SIZE:
                break
            offset += BATCH_SIZE
        return all_docs

    async def _store(self, docs: list[dict]) -> int:
        async with self.session_factory() as session:
            count = 0
            for doc in docs:
                normalized = _normalize(doc)
                if normalized is None:
                    continue
                result = await session.execute(
                    select(Vulnerability).where(
                        Vulnerability.cve_id == normalized["cve_id"],
                        Vulnerability.tenant_id == DEFAULT_TENANT_ID,
                        Vulnerability.package_name == normalized["package_name"],
                    )
                )
                existing = result.scalar_one_or_none()
                if existing:
                    existing.last_detected_at = normalized["last_detected_at"]
                    if normalized["cvss_score"] is not None:
                        existing.cvss_score = normalized["cvss_score"]
                    if normalized["severity"] is not None:
                        existing.severity = normalized["severity"]
                else:
                    vuln = Vulnerability(**normalized)
                    session.add(vuln)
                count += 1
            await session.commit()
        return count

    async def stop(self):
        await self.engine.dispose()
