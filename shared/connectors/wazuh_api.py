import httpx
import logging
from typing import Any

from shared.config import settings

logger = logging.getLogger(__name__)


class WazuhAPIConnector:
    def __init__(self):
        self.base_url = settings.wazuh_api_url.rstrip("/")
        self.auth = (settings.wazuh_api_user, settings.wazuh_api_password.get_secret_value())
        self.verify = settings.wazuh_api_verify_ssl
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
            resp = await client.get(f"{self.base_url}/health-check", headers={"Content-Type": "application/json"})
            resp.raise_for_status()
            return {"connected": True, "status_code": resp.status_code}
        except Exception as e:
            logger.warning("Wazuh API health check failed: %s", e)
            return {"connected": False, "error": str(e)}

    async def get_agents(self, limit: int = 100, offset: int = 0) -> list[dict]:
        try:
            client = await self._get_client()
            resp = await client.get(
                f"{self.base_url}/agents",
                params={"limit": limit, "offset": offset},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("Failed to fetch agents: %s", e)
            return []

    async def get_agent_groups(self) -> list[str]:
        try:
            client = await self._get_client()
            resp = await client.get(
                f"{self.base_url}/agents/groups",
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("Failed to fetch agent groups: %s", e)
            return []

    async def get_rules(self, limit: int = 100) -> list[dict]:
        try:
            client = await self._get_client()
            resp = await client.get(
                f"{self.base_url}/rules",
                params={"limit": limit},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.error("Failed to fetch rules: %s", e)
            return []

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
