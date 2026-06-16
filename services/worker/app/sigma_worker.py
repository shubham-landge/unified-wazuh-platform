import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shared.config import settings
from shared.models.alert import Alert

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = {"critical": 12, "high": 10, "medium": 7, "low": 3}


class SigmaWorker:
    def __init__(
        self,
        rules_dir: str | None = None,
        interval_seconds: int | None = None,
        indexer_url: str | None = None,
        index_name: str = "wazuh-alerts-*",
        tenant_id: str | None = None,
        session_factory=None,
    ):
        self.rules_dir = Path(rules_dir or os.getenv("SIGMA_RULES_DIR", "/app/sigma/rules"))
        self.interval_seconds = interval_seconds or int(os.getenv("SIGMA_WORKER_INTERVAL_SECONDS", "3600"))
        self.indexer_url = (indexer_url or settings.wazuh_indexer_url).rstrip("/")
        self.index_name = index_name
        self.tenant_id = self._resolve_tenant_id(tenant_id)
        self._engine = None
        if session_factory is None:
            self._engine = create_async_engine(settings.database_url, pool_size=2)
            self.session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        else:
            self.session_factory = session_factory
        self._stopped = asyncio.Event()

    def _session_context(self):
        factory = self.session_factory
        if hasattr(factory, "__aenter__") and hasattr(factory, "__aexit__"):
            return factory
        return factory()

    @staticmethod
    def _resolve_tenant_id(tenant_id: str | None) -> uuid.UUID:
        if tenant_id:
            try:
                return uuid.UUID(str(tenant_id))
            except Exception:
                pass
        try:
            return uuid.UUID(settings.tenant_id)
        except Exception:
            return uuid.UUID("00000000-0000-0000-0000-000000000001")

    async def start(self):
        while not self._stopped.is_set():
            try:
                await self.scan_once()
            except Exception as exc:
                logger.error("Sigma worker scan failed: %s", exc, exc_info=True)
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=self.interval_seconds)
            except asyncio.TimeoutError:
                pass

    async def stop(self):
        self._stopped.set()
        if self._engine:
            await self._engine.dispose()

    async def scan_once(self) -> dict[str, Any]:
        rules = self.load_rules()
        if not rules:
            return {"success": True, "rules": 0, "matches": 0}

        matches = 0
        async with self._session_context() as session:
            for rule in rules:
                query = self.compile_rule(rule)
                if not query:
                    continue
                hits = await self._search_indexer(query)
                for hit in hits:
                    if await self._raise_alert(session, rule, hit):
                        matches += 1
            await session.commit()
        return {"success": True, "rules": len(rules), "matches": matches}

    def load_rules(self) -> list[dict]:
        if not self.rules_dir.exists():
            return []
        rules: list[dict] = []
        for path in sorted(self.rules_dir.rglob("*.yml")) + sorted(self.rules_dir.rglob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text()) or {}
            except Exception as exc:
                logger.warning("Failed to load Sigma rule %s: %s", path, exc)
                continue
            if isinstance(data, dict):
                data["_source_file"] = str(path)
                rules.append(data)
        return rules

    def compile_rule(self, rule: dict) -> dict[str, Any] | None:
        detection = rule.get("detection") or {}
        if not isinstance(detection, dict):
            return None
        condition = str(detection.get("condition", "selection")).strip()
        selections = {key: value for key, value in detection.items() if key != "condition"}
        query = self._compile_condition(condition, selections)
        if not query:
            return None
        return {"query": query}

    def _compile_condition(self, condition: str, selections: dict) -> dict[str, Any] | None:
        if not selections:
            return None
        if " or " in condition:
            parts = [part.strip() for part in condition.split(" or ") if part.strip()]
            return {
                "bool": {
                    "should": [
                        self._compile_condition(part, selections) for part in parts if self._compile_condition(part, selections)
                    ],
                    "minimum_should_match": 1,
                }
            }
        if " and " in condition:
            parts = [part.strip() for part in condition.split(" and ") if part.strip()]
            return {
                "bool": {
                    "filter": [
                        self._compile_condition(part, selections) for part in parts if self._compile_condition(part, selections)
                    ]
                }
            }
        if condition in selections:
            return self._compile_selection(selections[condition])
        if "selection" in selections:
            return self._compile_selection(selections["selection"])
        first = next(iter(selections.values()))
        return self._compile_selection(first)

    def _compile_selection(self, selection: dict) -> dict[str, Any] | None:
        if not isinstance(selection, dict) or not selection:
            return None
        filters: list[dict[str, Any]] = []
        for key, value in selection.items():
            field, *mods = key.split("|")
            mod_set = {mod.strip().lower() for mod in mods}
            filters.extend(self._field_filters(field, value, mod_set))
        return {"bool": {"filter": filters}} if filters else None

    def _field_filters(self, field: str, value: Any, mods: set[str]) -> list[dict[str, Any]]:
        if isinstance(value, list):
            if "contains" in mods or "all" in mods:
                return [{"wildcard": {field: f"*{item}*"}} for item in value]
            return [{"terms": {field: [self._scalar(item) for item in value]}}]
        if "contains" in mods:
            return [{"wildcard": {field: f"*{self._scalar(value)}*"}}]
        if "startswith" in mods:
            return [{"wildcard": {field: f"{self._scalar(value)}*"}}]
        if "endswith" in mods:
            return [{"wildcard": {field: f"*{self._scalar(value)}"}}]
        if "re" in mods:
            return [{"regexp": {field: self._scalar(value)}}]
        return [{"term": {field: self._scalar(value)}}]

    @staticmethod
    def _scalar(value: Any) -> Any:
        if isinstance(value, (str, int, float, bool)):
            return value
        return str(value)

    async def _search_indexer(self, query: dict[str, Any]) -> list[dict]:
        auth = (settings.wazuh_indexer_user, settings.wazuh_indexer_password.get_secret_value())
        try:
            async with httpx.AsyncClient(
                verify=settings.wazuh_indexer_verify_ssl,
                timeout=30.0,
                auth=auth,
            ) as client:
                response = await client.post(
                    f"{self.indexer_url}/{self.index_name}/_search",
                    json=query,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            return hits if isinstance(hits, list) else []
        except Exception as exc:
            logger.error("Sigma indexer search failed: %s", exc)
            return []

    async def _raise_alert(self, session, rule: dict, hit: dict) -> bool:
        source = hit.get("_source") if isinstance(hit, dict) else {}
        if not isinstance(source, dict):
            source = {}
        sigma_id = str(rule.get("id") or rule.get("title") or "sigma")
        hit_id = str(hit.get("_id") or source.get("id") or uuid.uuid4())
        wazuh_alert_id = f"sigma:{sigma_id}:{hit_id}"
        existing = await session.execute(select(Alert).where(Alert.wazuh_alert_id == wazuh_alert_id))
        if existing.scalar_one_or_none():
            return False
        severity = str(rule.get("level") or rule.get("severity") or "medium").lower()
        alert = Alert(
            tenant_id=self.tenant_id,
            wazuh_alert_id=wazuh_alert_id,
            rule_id=self._rule_id(rule),
            rule_description=rule.get("description") or rule.get("title") or "Sigma match",
            rule_level=SEVERITY_LEVELS.get(severity, 7),
            rule_groups=list(rule.get("tags") or []),
            agent_id=self._pick(source, ("agent", "id"), "agent_id"),
            agent_name=self._pick(source, ("agent", "name"), "agent_name"),
            agent_ip=self._pick(source, ("agent", "ip"), "agent_ip"),
            source_ip=self._pick(source, ("source", "ip"), "source_ip", "src_ip"),
            destination_ip=self._pick(source, ("destination", "ip"), "destination_ip", "dst_ip"),
            user_name=self._pick(source, ("user", "name"), "user_name"),
            process_name=self._pick(source, ("process", "name"), "process_name"),
            event_id=str(self._pick(source, None, "event_id", "id", default=hit_id)),
            event_type="sigma",
            event_action="match",
            log_source="sigma-worker",
            raw_alert_redacted={"sigma_rule": self._jsonable(rule), "sigma_hit": self._jsonable(hit)},
            alert_timestamp=self._timestamp(source),
        )
        session.add(alert)
        logger.info("Raised Sigma alert %s", wazuh_alert_id)
        return True

    @staticmethod
    def _rule_id(rule: dict) -> int | None:
        raw = rule.get("id")
        if isinstance(raw, int):
            return raw
        if isinstance(raw, str) and raw.isdigit():
            return int(raw)
        return None

    @staticmethod
    def _pick(source: dict, nested: tuple[str, str] | None, *keys: str, default: Any = None) -> Any:
        if nested:
            outer, inner = nested
            value = source.get(outer)
            if isinstance(value, dict) and inner in value:
                return value.get(inner)
        for key in keys:
            if key in source:
                return source.get(key)
        return default

    @staticmethod
    def _timestamp(source: dict) -> datetime:
        raw = source.get("@timestamp") or source.get("timestamp") or source.get("event", {}).get("created")
        if isinstance(raw, datetime):
            return raw
        if isinstance(raw, str):
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except Exception:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _jsonable(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: SigmaWorker._jsonable(val) for key, val in value.items()}
        if isinstance(value, list):
            return [SigmaWorker._jsonable(item) for item in value]
        if isinstance(value, tuple):
            return [SigmaWorker._jsonable(item) for item in value]
        if isinstance(value, uuid.UUID):
            return str(value)
        if isinstance(value, datetime):
            return value.isoformat()
        return value
