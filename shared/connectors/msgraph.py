import logging
from time import perf_counter

import httpx

logger = logging.getLogger(__name__)


class MSGraphConnector:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    async def get_risky_signins(self, limit: int = 100) -> list[dict]:
        return await self._get_collection("identityProtection/riskySignIns", limit=limit)

    async def get_risky_users(self, limit: int = 100) -> list[dict]:
        return await self._get_collection("identityProtection/riskyUsers", limit=limit)

    async def get_oauth_grants(self, limit: int = 100) -> list[dict]:
        return await self._get_collection("oauth2PermissionGrants", limit=limit)

    async def health(self) -> dict:
        started = perf_counter()
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(f"{self.base_url}/health")
                resp.raise_for_status()
            return {"connected": True, "latency_ms": round((perf_counter() - started) * 1000)}
        except Exception as exc:
            logger.error("MS Graph health failed: %s", exc)
            return {"connected": False, "error": str(exc), "latency_ms": round((perf_counter() - started) * 1000)}

    async def _get_collection(self, path: str, limit: int = 100) -> list[dict]:
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(f"{self.base_url}/{path}", params={"$top": limit})
                resp.raise_for_status()
                data = resp.json()
            return data.get("value", []) if isinstance(data, dict) else []
        except Exception as exc:
            logger.error("MS Graph fetch failed for %s: %s", path, exc)
            return []
