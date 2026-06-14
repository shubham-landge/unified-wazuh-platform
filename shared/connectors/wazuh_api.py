import httpx
import logging
from typing import Any

from shared.config import settings

logger = logging.getLogger(__name__)


class WazuhAPIConnector:
    def __init__(
        self,
        base_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        verify: bool | None = None,
        label: str | None = None,
    ):
        self.base_url = (base_url or settings.wazuh_api_url).rstrip("/")
        self.auth = (
            user if user is not None else settings.wazuh_api_user,
            password if password is not None else settings.wazuh_api_password.get_secret_value(),
        )
        self.verify = verify if verify is not None else settings.wazuh_api_verify_ssl
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
            resp = await client.get(f"{self.base_url}/health-check", headers={"Content-Type": "application/json"})
            resp.raise_for_status()
            return {"connected": True, "label": self.label, "status_code": resp.status_code}
        except Exception as e:
            logger.warning("Wazuh API health check failed: %s", e)
            return {"connected": False, "label": self.label, "error": str(e)}

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
