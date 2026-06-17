import logging
from time import perf_counter

import httpx

logger = logging.getLogger(__name__)


class CloudTrailConnector:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    async def get_events(self, limit: int = 100) -> list[dict]:
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(f"{self.base_url}/events", params={"limit": limit})
                resp.raise_for_status()
                data = resp.json()
            return data.get("events", []) if isinstance(data, dict) else []
        except Exception as exc:
            logger.error("CloudTrail fetch failed: %s", exc)
            return []

    async def health(self) -> dict:
        started = perf_counter()
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(f"{self.base_url}/health")
                resp.raise_for_status()
            return {"connected": True, "latency_ms": round((perf_counter() - started) * 1000)}
        except Exception as exc:
            return {"connected": False, "error": str(exc), "latency_ms": round((perf_counter() - started) * 1000)}
