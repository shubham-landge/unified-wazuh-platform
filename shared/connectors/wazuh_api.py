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
        self._user = user if user is not None else settings.wazuh_api_user
        self._password = (
            password if password is not None else settings.wazuh_api_password.get_secret_value()
        )
        self.verify = verify if verify is not None else settings.wazuh_api_verify_ssl
        self.label = label
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None

    async def _ensure_token(self) -> str:
        if self._token:
            return self._token
        async with httpx.AsyncClient(verify=self.verify, timeout=httpx.Timeout(10.0, read=30.0)) as client:
            resp = await client.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self._user, self._password),
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data["data"]["token"]
            return self._token

    async def _get_client(self) -> httpx.AsyncClient:
        if not self._client:
            token = await self._ensure_token()
            self._client = httpx.AsyncClient(
                verify=self.verify,
                timeout=httpx.Timeout(10.0, read=30.0),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def _reauthenticate(self):
        await self.close()
        self._token = None
        return await self._get_client()

    async def health(self) -> dict:
        try:
            client = await self._get_client()
            resp = await client.get(f"{self.base_url}/")
            resp.raise_for_status()
            return {"connected": True, "label": self.label, "status_code": resp.status_code}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                try:
                    client = await self._reauthenticate()
                    resp = await client.get(f"{self.base_url}/")
                    resp.raise_for_status()
                    return {"connected": True, "label": self.label, "status_code": resp.status_code}
                except Exception as re:
                    logger.warning("Wazuh API re-auth health check failed: %s", re)
                    return {"connected": False, "label": self.label, "error": str(re)}
            logger.warning("Wazuh API health check failed: %s", e)
            return {"connected": False, "label": self.label, "error": str(e)}
        except Exception as e:
            logger.warning("Wazuh API health check failed: %s", e)
            return {"connected": False, "label": self.label, "error": str(e)}

    async def get_agents(self, limit: int = 100, offset: int = 0) -> list[dict]:
        try:
            client = await self._get_client()
            resp = await client.get(
                f"{self.base_url}/agents",
                params={"limit": limit, "offset": offset},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", {}).get("affected_items", [])
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                try:
                    client = await self._reauthenticate()
                    resp = await client.get(
                        f"{self.base_url}/agents",
                        params={"limit": limit, "offset": offset},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    return data.get("data", {}).get("affected_items", [])
                except Exception as re:
                    logger.error("Failed to fetch agents after re-auth: %s", re)
                    return []
            logger.error("Failed to fetch agents: %s", e)
            return []
        except Exception as e:
            logger.error("Failed to fetch agents: %s", e)
            return []

    async def get_agent_groups(self) -> list[str]:
        try:
            client = await self._get_client()
            resp = await client.get(f"{self.base_url}/agents/groups")
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", {}).get("affected_items", [])
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                try:
                    client = await self._reauthenticate()
                    resp = await client.get(f"{self.base_url}/agents/groups")
                    resp.raise_for_status()
                    data = resp.json()
                    return data.get("data", {}).get("affected_items", [])
                except Exception as re:
                    logger.error("Failed to fetch agent groups after re-auth: %s", re)
                    return []
            logger.error("Failed to fetch agent groups: %s", e)
            return []
        except Exception as e:
            logger.error("Failed to fetch agent groups: %s", e)
            return []

    async def get_rules(self, limit: int = 100) -> list[dict]:
        try:
            client = await self._get_client()
            resp = await client.get(
                f"{self.base_url}/rules",
                params={"limit": limit},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", {}).get("affected_items", [])
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                try:
                    client = await self._reauthenticate()
                    resp = await client.get(
                        f"{self.base_url}/rules",
                        params={"limit": limit},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    return data.get("data", {}).get("affected_items", [])
                except Exception as re:
                    logger.error("Failed to fetch rules after re-auth: %s", re)
                    return []
            logger.error("Failed to fetch rules: %s", e)
            return []
        except Exception as e:
            logger.error("Failed to fetch rules: %s", e)
            return []

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
        self._token = None
