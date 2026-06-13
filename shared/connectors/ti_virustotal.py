import logging
from hashlib import md5
import httpx

from shared.config import settings

logger = logging.getLogger(__name__)

_BASE = "https://www.virustotal.com/api/v3"

_ENDPOINTS = {
    "hash_md5":    "files/{value}",
    "hash_sha256": "files/{value}",
    "hash_sha1":   "files/{value}",
    "ip":          "ip_addresses/{value}",
    "domain":      "domains/{value}",
    "url":         "urls/{value}",
}


class VirusTotalConnector:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or (
            settings.virustotal_api_key.get_secret_value() if settings.virustotal_api_key else ""
        )

    def _headers(self) -> dict:
        return {"x-apikey": self.api_key}

    def _url_id(self, url: str) -> str:
        """VT requires base64url-encoded URL for URL lookups."""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    async def lookup(self, ioc_type: str, value: str) -> dict:
        if not self.api_key:
            return {"found": False, "error": "VirusTotal API key not configured"}

        endpoint_tpl = _ENDPOINTS.get(ioc_type)
        if not endpoint_tpl:
            return {"found": False, "error": f"Unsupported IOC type: {ioc_type}"}

        lookup_value = self._url_id(value) if ioc_type == "url" else value
        url = f"{_BASE}/{endpoint_tpl.format(value=lookup_value)}"

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(url, headers=self._headers())
                if resp.status_code == 404:
                    return {"found": False, "source": "virustotal"}
                if resp.status_code == 429:
                    return {"found": False, "source": "virustotal", "error": "Rate limit exceeded"}
                resp.raise_for_status()
                data = resp.json()

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values()) if stats else 0

            threat_score = min((malicious + suspicious) / max(total_engines, 1) * 100, 100) if total_engines else 0
            confidence = min(0.3 + (malicious / max(total_engines, 1)) * 0.7, 1.0) if total_engines else 0.0

            malware_families = list({
                result.get("result", "")
                for result in attrs.get("last_analysis_results", {}).values()
                if result.get("category") in ("malicious", "suspicious") and result.get("result")
            })[:10]

            tags = attrs.get("tags", [])

            return {
                "found": malicious > 0 or suspicious > 0,
                "source": "virustotal",
                "ioc_type": ioc_type,
                "ioc_value": value,
                "threat_score": round(threat_score, 1),
                "confidence": round(confidence, 2),
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total_engines,
                "malware_families": malware_families,
                "tags": tags,
                "reputation": attrs.get("reputation", 0),
                "raw_data": {"stats": stats, "attributes_subset": {k: attrs[k] for k in ["reputation", "tags"] if k in attrs}},
            }
        except Exception as e:
            logger.error("VT lookup failed for %s/%s: %s", ioc_type, value, e)
            return {"found": False, "source": "virustotal", "error": str(e)}

    async def health(self) -> dict:
        if not self.api_key:
            return {"connected": False, "error": "API key not configured"}
        # Use a known benign hash to verify connectivity
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{_BASE}/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    headers=self._headers(),
                )
                if resp.status_code in (200, 404):
                    return {"connected": True}
                return {"connected": False, "status_code": resp.status_code}
        except Exception as e:
            return {"connected": False, "error": str(e)}
