import logging
from time import perf_counter

import httpx

from shared.config import settings

logger = logging.getLogger(__name__)


class MaigretConnector:
    def __init__(self, maigret_url: str | None = None):
        self.maigret_url = (maigret_url or settings.osint_maigret_url).rstrip("/")

    async def lookup_username(self, username: str) -> list[dict]:
        started = perf_counter()
        payload = {"username": username}
        try:
            async with httpx.AsyncClient(timeout=settings.osint_sandbox_timeout) as client:
                response = await client.post(f"{self.maigret_url}/lookup", json=payload)
                response.raise_for_status()
            data = response.json()
            return self._normalize_results(data, started)
        except Exception as exc:
            logger.error("Maigret lookup failed for %s: %s", username, exc)
            return []

    async def health(self) -> dict:
        started = perf_counter()
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{self.maigret_url}/health")
                response.raise_for_status()
            data = response.json()
            connected = bool(data.get("connected", True)) if isinstance(data, dict) else True
            return {
                "success": True,
                "connected": connected,
                "base_url": self.maigret_url,
                "latency_ms": round((perf_counter() - started) * 1000),
            }
        except Exception as exc:
            return {
                "success": False,
                "connected": False,
                "base_url": self.maigret_url,
                "error": str(exc),
                "latency_ms": round((perf_counter() - started) * 1000),
            }

    def _normalize_results(self, data, started: float) -> list[dict]:
        items: list[dict] = []
        if isinstance(data, list):
            raw_items = data
        elif isinstance(data, dict):
            raw_items = (
                data.get("results")
                or data.get("data")
                or data.get("items")
                or data.get("profiles")
                or []
            )
        else:
            raw_items = []

        if isinstance(raw_items, dict):
            raw_items = [raw_items]

        for item in raw_items:
            if not isinstance(item, dict):
                continue
            items.append(
                {
                    "source": item.get("source") or item.get("site") or item.get("platform") or "unknown",
                    "profile_url": item.get("profile_url") or item.get("url") or item.get("link"),
                    "name": item.get("name") or item.get("title") or item.get("display_name"),
                    "location": item.get("location") or item.get("country") or item.get("city"),
                    "raw_data": item,
                    "latency_ms": round((perf_counter() - started) * 1000),
                }
            )
        return items
