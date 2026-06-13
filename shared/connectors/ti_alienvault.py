import logging
from datetime import datetime, timezone
import httpx

from shared.config import settings

logger = logging.getLogger(__name__)

_BASE = "https://otx.alienvault.com/api/v1"

_INDICATOR_TYPES = {
    "ip":          "IPv4",
    "domain":      "domain",
    "url":         "url",
    "hash_md5":    "file",
    "hash_sha256": "file",
    "hash_sha1":   "file",
}


class AlienVaultOTXConnector:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or (
            settings.otx_api_key.get_secret_value() if settings.otx_api_key else ""
        )

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key, "Content-Type": "application/json"}

    async def lookup(self, ioc_type: str, value: str) -> dict:
        """Query OTX for a single IOC. Returns normalized result dict."""
        if not self.api_key:
            return {"found": False, "error": "OTX API key not configured"}

        indicator_type = _INDICATOR_TYPES.get(ioc_type)
        if not indicator_type:
            return {"found": False, "error": f"Unsupported IOC type: {ioc_type}"}

        # For file hashes, section is "analysis"; for network types it's "general"
        section = "analysis" if ioc_type.startswith("hash") else "general"

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    f"{_BASE}/indicators/{indicator_type}/{value}/{section}",
                    headers=self._headers(),
                )
                if resp.status_code == 404:
                    return {"found": False, "source": "otx"}
                resp.raise_for_status()
                data = resp.json()

            pulse_count = data.get("pulse_info", {}).get("count", 0)
            malware_families = list({
                pulse.get("malware_families", [{}])[0].get("display_name", "")
                for pulse in data.get("pulse_info", {}).get("pulses", [])
                if pulse.get("malware_families")
            })
            tags = list({
                tag
                for pulse in data.get("pulse_info", {}).get("pulses", [])
                for tag in pulse.get("tags", [])
            })[:20]

            return {
                "found": pulse_count > 0,
                "source": "otx",
                "ioc_type": ioc_type,
                "ioc_value": value,
                "threat_score": min(pulse_count * 5, 100),
                "confidence": min(0.4 + pulse_count * 0.06, 1.0),
                "pulse_count": pulse_count,
                "malware_families": malware_families,
                "tags": tags,
                "raw_data": data,
            }
        except Exception as e:
            logger.error("OTX lookup failed for %s/%s: %s", ioc_type, value, e)
            return {"found": False, "source": "otx", "error": str(e)}

    async def get_subscribed_pulses(self, limit: int = 100) -> list[dict]:
        """Fetch latest pulses from subscribed feeds."""
        if not self.api_key:
            return []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{_BASE}/pulses/subscribed",
                    headers=self._headers(),
                    params={"limit": limit},
                )
                resp.raise_for_status()
                return resp.json().get("results", [])
        except Exception as e:
            logger.error("OTX pulse fetch failed: %s", e)
            return []

    async def health(self) -> dict:
        if not self.api_key:
            return {"connected": False, "error": "API key not configured"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{_BASE}/user/me", headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
            return {"connected": True, "username": data.get("username")}
        except Exception as e:
            return {"connected": False, "error": str(e)}
