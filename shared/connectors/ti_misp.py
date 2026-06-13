import logging
from datetime import datetime, timezone
import httpx

from shared.config import settings

logger = logging.getLogger(__name__)

_MISP_TYPE_MAP = {
    "ip":          ["ip-src", "ip-dst"],
    "domain":      ["domain", "hostname"],
    "url":         ["url"],
    "hash_md5":    ["md5"],
    "hash_sha256": ["sha256"],
    "hash_sha1":   ["sha1"],
    "email":       ["email-src", "email-dst"],
}


class MISPConnector:
    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = (base_url or settings.misp_url or "").rstrip("/")
        self.api_key = api_key or (
            settings.misp_api_key.get_secret_value() if settings.misp_api_key else ""
        )
        self.verify_ssl = getattr(settings, "misp_verify_ssl", True)

    def _headers(self) -> dict:
        return {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def search(self, ioc_type: str, value: str, limit: int = 10) -> dict:
        if not self.base_url or not self.api_key:
            return {"found": False, "error": "MISP URL/API key not configured"}

        misp_types = _MISP_TYPE_MAP.get(ioc_type, [])
        if not misp_types:
            return {"found": False, "error": f"Unsupported IOC type: {ioc_type}"}

        try:
            async with httpx.AsyncClient(timeout=20.0, verify=self.verify_ssl) as client:
                resp = await client.post(
                    f"{self.base_url}/attributes/restSearch",
                    headers=self._headers(),
                    json={
                        "value": value,
                        "type": misp_types,
                        "limit": limit,
                        "returnFormat": "json",
                        "to_ids": True,
                    },
                )
                resp.raise_for_status()
                data = resp.json()

            attributes = data.get("response", {}).get("Attribute", [])
            if not attributes:
                return {"found": False, "source": "misp"}

            tags = list({tag["name"] for attr in attributes for tag in attr.get("Tag", [])})
            event_ids = list({attr.get("event_id") for attr in attributes if attr.get("event_id")})
            threat_levels = [int(attr.get("Event", {}).get("threat_level_id", 4)) for attr in attributes]
            avg_threat_level = sum(threat_levels) / len(threat_levels) if threat_levels else 4

            # MISP threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined
            threat_score = max(0, (4 - avg_threat_level) * 33)

            return {
                "found": True,
                "source": "misp",
                "ioc_type": ioc_type,
                "ioc_value": value,
                "threat_score": round(threat_score, 1),
                "confidence": min(0.5 + len(event_ids) * 0.05, 1.0),
                "attribute_count": len(attributes),
                "event_ids": event_ids[:5],
                "tags": tags[:20],
                "raw_data": {"attributes": attributes[:5]},
            }
        except Exception as e:
            logger.error("MISP search failed for %s/%s: %s", ioc_type, value, e)
            return {"found": False, "source": "misp", "error": str(e)}

    async def get_recent_events(self, days: int = 7, limit: int = 50) -> list[dict]:
        if not self.base_url or not self.api_key:
            return []
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=self.verify_ssl) as client:
                resp = await client.post(
                    f"{self.base_url}/events/restSearch",
                    headers=self._headers(),
                    json={
                        "last": f"{days}d",
                        "limit": limit,
                        "returnFormat": "json",
                        "published": True,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
            return data.get("response", [])
        except Exception as e:
            logger.error("MISP recent events failed: %s", e)
            return []

    async def health(self) -> dict:
        if not self.base_url or not self.api_key:
            return {"connected": False, "error": "MISP URL/API key not configured"}
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=self.verify_ssl) as client:
                resp = await client.get(f"{self.base_url}/servers/getVersion", headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
            return {"connected": True, "version": data.get("version")}
        except Exception as e:
            return {"connected": False, "error": str(e)}
