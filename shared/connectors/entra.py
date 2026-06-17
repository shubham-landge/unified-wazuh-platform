import logging
from time import perf_counter

import httpx

logger = logging.getLogger(__name__)


class EntraConnector:
    def __init__(self, base_url: str, tenant_id: str, client_id: str = "", client_secret: str = ""):
        self.base_url = base_url.rstrip("/")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    async def get_signins(self, limit: int = 100) -> list[dict]:
        return await self._get_collection("auditLogs/signIns", limit=limit)

    async def get_audit_logs(self, limit: int = 100) -> list[dict]:
        return await self._get_collection("auditLogs/directoryAudits", limit=limit)

    async def health(self) -> dict:
        started = perf_counter()
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(f"{self.base_url}/health")
                resp.raise_for_status()
            return {"connected": True, "latency_ms": round((perf_counter() - started) * 1000)}
        except Exception as exc:
            logger.error("Entra health failed: %s", exc)
            return {"connected": False, "error": str(exc), "latency_ms": round((perf_counter() - started) * 1000)}

    async def _get_collection(self, path: str, limit: int = 100) -> list[dict]:
        started = perf_counter()
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(f"{self.base_url}/{path}", params={"$top": limit})
                resp.raise_for_status()
                data = resp.json()
            items = data.get("value", []) if isinstance(data, dict) else []
            return [item for item in items if isinstance(item, dict)]
        except Exception as exc:
            logger.error("Entra collection %s failed: %s", path, exc)
            return []
