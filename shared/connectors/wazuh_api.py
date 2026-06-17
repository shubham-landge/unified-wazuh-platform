import httpx
import logging
from typing import Any

from shared.config import settings
from shared.connectors.circuit_breaker import CircuitBreaker

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
        self._cb = CircuitBreaker(name=f"wazuh_api:{label or 'default'}", failure_threshold=3, recovery_timeout=60.0)
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

    async def _cb_call(self, factory):
        """Execute a coroutine factory under circuit breaker protection."""
        return await self._cb.call(factory)

    async def health(self) -> dict:
        try:
            async def _do():
                client = await self._get_client()
                resp = await client.get(f"{self.base_url}/")
                resp.raise_for_status()
                return {"connected": True, "label": self.label, "status_code": resp.status_code}
            return await self._cb_call(_do)
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
            async def _do():
                client = await self._get_client()
                resp = await client.get(
                    f"{self.base_url}/agents",
                    params={"limit": limit, "offset": offset},
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("data", {}).get("affected_items", [])
            return await self._cb_call(_do)
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
            async def _do():
                client = await self._get_client()
                resp = await client.get(f"{self.base_url}/agents/groups")
                resp.raise_for_status()
                data = resp.json()
                return data.get("data", {}).get("affected_items", [])
            return await self._cb_call(_do)
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
            async def _do():
                client = await self._get_client()
                resp = await client.get(
                    f"{self.base_url}/rules",
                    params={"limit": limit},
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("data", {}).get("affected_items", [])
            return await self._cb_call(_do)
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

    async def _get_json(self, path: str, params: dict | None = None) -> dict:
        """GET a JSON endpoint with circuit-breaker + one re-auth retry.

        Returns the parsed JSON body (full envelope). Raises on failure so
        callers can decide how to degrade.
        """
        async def _do():
            client = await self._get_client()
            resp = await client.get(f"{self.base_url}{path}", params=params or {})
            resp.raise_for_status()
            return resp.json()

        try:
            return await self._cb_call(_do)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                client = await self._reauthenticate()
                resp = await client.get(f"{self.base_url}{path}", params=params or {})
                resp.raise_for_status()
                return resp.json()
            raise

    async def get_agents_summary(self) -> dict:
        """Agent connectivity counts: active / disconnected / never_connected / pending."""
        try:
            data = await self._get_json("/agents/summary/status")
            d = data.get("data", {})
            # Wazuh returns either flat counts or a 'connection' sub-dict by version.
            conn = d.get("connection", d)
            return {
                "active": conn.get("active", 0),
                "disconnected": conn.get("disconnected", 0),
                "never_connected": conn.get("never_connected", 0),
                "pending": conn.get("pending", 0),
                "total": conn.get("total", 0),
                "label": self.label,
            }
        except Exception as e:
            logger.warning("Failed to fetch agent summary: %s", e)
            return {"active": 0, "disconnected": 0, "never_connected": 0,
                    "pending": 0, "total": 0, "label": self.label, "error": str(e)}

    async def get_cluster_health(self) -> dict:
        """Cluster node health. Tolerates single-node (cluster disabled) managers."""
        try:
            status = await self._get_json("/cluster/status")
            enabled = status.get("data", {}).get("enabled", "no") == "yes"
            if not enabled:
                return {"enabled": False, "status": "standalone", "nodes": 1, "label": self.label}
            hc = await self._get_json("/cluster/healthcheck")
            nodes = hc.get("data", {}).get("affected_items", [])
            return {"enabled": True, "status": "ok" if nodes else "unknown",
                    "nodes": len(nodes), "label": self.label}
        except Exception as e:
            logger.warning("Failed to fetch cluster health: %s", e)
            return {"enabled": False, "status": "error", "nodes": 0,
                    "label": self.label, "error": str(e)}

    async def get_manager_stats(self) -> dict:
        """analysisd throughput: events received/dropped and queue usage."""
        try:
            data = await self._get_json("/manager/stats/analysisd")
            items = data.get("data", {}).get("affected_items", [])
            stats = items[0] if items else {}
            return {
                "events_received": stats.get("total_events_decoded", stats.get("events_received", 0)),
                "events_dropped": stats.get("events_dropped", 0),
                "event_queue_usage": stats.get("event_queue_usage", 0.0),
                "rule_matching_queue_usage": stats.get("rule_matching_queue_usage", 0.0),
                "label": self.label,
            }
        except Exception as e:
            logger.warning("Failed to fetch manager stats: %s", e)
            return {"events_received": 0, "events_dropped": 0, "event_queue_usage": 0.0,
                    "rule_matching_queue_usage": 0.0, "label": self.label, "error": str(e)}

    async def get_manager_status(self) -> dict:
        """Daemon run-state map; flags any daemon not 'running'."""
        try:
            data = await self._get_json("/manager/status")
            daemons = data.get("data", {}).get("affected_items", [{}])
            daemon_map = daemons[0] if daemons else {}
            stopped = [name for name, state in daemon_map.items() if state != "running"]
            return {"daemons": daemon_map, "all_running": not stopped,
                    "stopped": stopped, "label": self.label}
        except Exception as e:
            logger.warning("Failed to fetch manager status: %s", e)
            return {"daemons": {}, "all_running": False, "stopped": [],
                    "label": self.label, "error": str(e)}

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
        self._token = None
