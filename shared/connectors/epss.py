from datetime import datetime, timezone

import httpx

EPSS_URL = "https://api.first.org/data/v1.0/epss"


async def fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    if not cve_ids:
        return {}

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.get(
            EPSS_URL,
            params={"cve": ",".join(cve_ids)},
        )
        response.raise_for_status()

    fetched_at = datetime.now(timezone.utc).isoformat()
    return {
        item["cve"].upper(): {
            "epss_score": float(item.get("epss", 0.0)),
            "epss_percentile": float(item.get("percentile", 0.0)),
            "fetched_at": fetched_at,
        }
        for item in response.json().get("data", [])
        if item.get("cve")
    }
