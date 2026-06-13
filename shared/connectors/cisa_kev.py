from datetime import datetime, timedelta, timezone

import httpx

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CACHE_TTL = timedelta(hours=6)
_cache: dict[str, object] = {"expires_at": None, "cves": set()}


async def fetch_kev_catalog() -> set[str]:
    now = datetime.now(timezone.utc)
    expires_at = _cache["expires_at"]
    if expires_at and expires_at > now:
        return set(_cache["cves"])

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.get(CISA_KEV_URL)
        response.raise_for_status()

    cves = {
        item["cveID"].upper()
        for item in response.json().get("vulnerabilities", [])
        if item.get("cveID")
    }
    _cache.update({"expires_at": now + CACHE_TTL, "cves": cves})
    return cves
