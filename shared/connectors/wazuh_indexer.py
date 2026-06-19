import httpx
import logging
from typing import Any
from datetime import datetime, timedelta, timezone

from shared.config import settings
from shared.connectors.circuit_breaker import CircuitBreaker

logger = logging.getLogger(__name__)


class WazuhIndexerConnector:
    def __init__(
        self,
        base_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        verify: bool | None = None,
        label: str | None = None,
    ):
        self.base_url = (base_url or settings.wazuh_indexer_url).rstrip("/")
        self.auth = (
            user if user is not None else settings.wazuh_indexer_user,
            password if password is not None else settings.wazuh_indexer_password.get_secret_value(),
        )
        self.verify = verify if verify is not None else settings.wazuh_indexer_verify_ssl
        self.label = label
        self._client: httpx.AsyncClient | None = None
        self._cb = CircuitBreaker(name=f"wazuh_indexer:{label or 'default'}", failure_threshold=3, recovery_timeout=60.0)

    async def _get_client(self) -> httpx.AsyncClient:
        if not self._client:
            self._client = httpx.AsyncClient(
                verify=self.verify,
                timeout=httpx.Timeout(30.0),
                auth=self.auth,
            )
        return self._client

    async def _cb_call(self, factory):
        return await self._cb.call(factory)

    async def health(self) -> dict:
        try:
            async def _do():
                client = await self._get_client()
                resp = await client.get(f"{self.base_url}/_cluster/health")
                resp.raise_for_status()
                data = resp.json()
                return {
                    "connected": True,
                    "label": self.label,
                    "cluster_name": data.get("cluster_name"),
                    "status": data.get("status"),
                    "nodes": data.get("number_of_nodes"),
                }
            return await self._cb_call(_do)
        except Exception as e:
            logger.warning("Indexer health check failed: %s", e)
            return {"connected": False, "label": self.label, "error": str(e)}

    async def search_alerts(
        self,
        index: str = "wazuh-alerts-*",
        lookback_hours: int = 24,
        size: int = 100,
    ) -> list[dict]:
        try:
            async def _do():
                client = await self._get_client()
                since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
                query = {
                    "query": {
                        "bool": {
                            "filter": [
                                {"range": {"@timestamp": {"gte": since}}}
                            ]
                        }
                    },
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "size": size,
                }
                resp = await client.post(
                    f"{self.base_url}/{index}/_search",
                    json=query,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
                hits = data.get("hits", {}).get("hits", [])
                return [h.get("_source", {}) for h in hits]
            return await self._cb_call(_do)
        except Exception as e:
            logger.error("Failed to search alerts: %s", e)
            return []

    async def search_vulnerabilities(self, size: int = 100) -> list[dict]:
        try:
            client = await self._get_client()
            query = {
                "query": {"match_all": {}},
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": size,
            }
            resp = await client.post(
                f"{self.base_url}/wazuh-vulnerabilities-*/_search",
                json=query,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            hits = data.get("hits", {}).get("hits", [])
            return [h.get("_source", {}) for h in hits]
        except Exception as e:
            logger.error("Failed to search vulnerabilities: %s", e)
            return []

    async def cluster_health(self) -> dict:
        """Detailed cluster health: status, shard allocation, node count."""
        try:
            async def _do():
                client = await self._get_client()
                resp = await client.get(f"{self.base_url}/_cluster/health")
                resp.raise_for_status()
                data = resp.json()
                return {
                    "status": data.get("status", "unknown"),
                    "nodes": data.get("number_of_nodes", 0),
                    "active_shards": data.get("active_shards", 0),
                    "unassigned_shards": data.get("unassigned_shards", 0),
                    "active_shards_percent": data.get("active_shards_percent_as_number", 0.0),
                    "label": self.label,
                }
            return await self._cb_call(_do)
        except Exception as e:
            logger.warning("Indexer cluster health failed: %s", e)
            return {"status": "error", "nodes": 0, "active_shards": 0,
                    "unassigned_shards": 0, "active_shards_percent": 0.0,
                    "label": self.label, "error": str(e)}

    async def ingestion_lag_seconds(self, index: str = "wazuh-alerts-*") -> float | None:
        """Seconds between now and the newest alert's @timestamp.

        High lag means events are arriving late (pipeline backpressure) or the
        managers stopped shipping. Returns None when no alerts are found.
        """
        try:
            async def _do():
                client = await self._get_client()
                query = {
                    "size": 1,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "_source": ["@timestamp"],
                }
                resp = await client.post(
                    f"{self.base_url}/{index}/_search",
                    json=query,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                hits = resp.json().get("hits", {}).get("hits", [])
                if not hits:
                    return None
                ts = hits[0].get("_source", {}).get("@timestamp")
                if not ts:
                    return None
                newest = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return max(0.0, (datetime.now(timezone.utc) - newest).total_seconds())
            return await self._cb_call(_do)
        except Exception as e:
            logger.warning("Failed to compute ingestion lag: %s", e)
            return None

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
