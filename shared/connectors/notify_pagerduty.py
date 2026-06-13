import logging
import httpx

from shared.config import settings

logger = logging.getLogger(__name__)

_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
}


class PagerDutyConnector:
    def __init__(self, routing_key: str | None = None):
        self.routing_key = routing_key or (
            settings.pagerduty_routing_key.get_secret_value()
            if settings.pagerduty_routing_key else ""
        )

    async def trigger(
        self,
        summary: str,
        source: str,
        severity: str = "error",
        dedup_key: str | None = None,
        details: dict | None = None,
        links: list[dict] | None = None,
    ) -> dict:
        if not self.routing_key:
            return {"success": False, "error": "PagerDuty routing key not configured"}

        pd_severity = _SEVERITY_MAP.get(severity.lower(), "error")

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": summary[:1024],
                "source": source,
                "severity": pd_severity,
                "custom_details": details or {},
            },
        }
        if dedup_key:
            payload["dedup_key"] = dedup_key
        if links:
            payload["links"] = links

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(_EVENTS_URL, json=payload)
                resp.raise_for_status()
                data = resp.json()
            logger.info("PagerDuty event triggered | dedup_key=%s status=%s", dedup_key, data.get("status"))
            return {"success": True, "dedup_key": data.get("dedup_key"), "status": data.get("status")}
        except Exception as e:
            logger.error("PagerDuty trigger failed: %s", e)
            return {"success": False, "error": str(e)}

    async def resolve(self, dedup_key: str) -> dict:
        if not self.routing_key:
            return {"success": False, "error": "PagerDuty routing key not configured"}

        payload = {
            "routing_key": self.routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(_EVENTS_URL, json=payload)
                resp.raise_for_status()
            logger.info("PagerDuty event resolved | dedup_key=%s", dedup_key)
            return {"success": True}
        except Exception as e:
            logger.error("PagerDuty resolve failed: %s", e)
            return {"success": False, "error": str(e)}

    async def health(self) -> dict:
        if not self.routing_key:
            return {"connected": False, "error": "No routing key configured"}
        return {"connected": True, "routing_key_configured": True}
