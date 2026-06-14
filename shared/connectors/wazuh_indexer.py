import httpx
import logging
from typing import Any
from datetime import datetime, timedelta, timezone

from shared.config import settings

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

    async def _get_client(self) -> httpx.AsyncClient:
        if not self._client:
            self._client = httpx.AsyncClient(
                verify=self.verify,
                timeout=httpx.Timeout(connect=10.0, read=30.0),
                auth=self.auth,
            )
        return self._client

    async def health(self) -> dict:
        try:
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

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
