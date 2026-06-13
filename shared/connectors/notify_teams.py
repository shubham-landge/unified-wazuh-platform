import logging
import httpx

from shared.config import settings

logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "critical": "FF0000",
    "high":     "FF6600",
    "medium":   "FFCC00",
    "low":      "00CC00",
}


class TeamsConnector:
    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or settings.teams_webhook_url

    async def send(self, title: str, summary: str, facts: list[dict] | None = None, color: str = "0078D4") -> dict:
        if not self.webhook_url:
            return {"success": False, "error": "Teams webhook URL not configured"}

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": self._build_adaptive_card(title, summary, facts or [], color),
                }
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(self.webhook_url, json=card)
                resp.raise_for_status()
            logger.info("Teams message sent | title=%s", title)
            return {"success": True}
        except Exception as e:
            logger.error("Teams send failed: %s", e)
            return {"success": False, "error": str(e)}

    def _build_adaptive_card(self, title: str, summary: str, facts: list[dict], color: str) -> dict:
        body = [
            {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": title, "wrap": True},
            {"type": "TextBlock", "text": summary, "wrap": True, "spacing": "Medium"},
        ]
        if facts:
            body.append({
                "type": "FactSet",
                "facts": [{"title": f["title"], "value": str(f["value"])} for f in facts],
                "spacing": "Medium",
            })
        return {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "msteams": {"width": "Full"},
            "body": body,
        }

    def build_alert_facts(self, alert: dict, triage: dict | None = None) -> tuple[str, list[dict]]:
        severity = triage.get("severity", "unknown") if triage else "unknown"
        color = _SEVERITY_COLORS.get(severity, "0078D4")
        facts = [
            {"title": "Severity", "value": severity.upper()},
            {"title": "Rule", "value": alert.get("rule_description", "N/A")},
            {"title": "Agent", "value": alert.get("agent_name", "N/A")},
            {"title": "Source IP", "value": alert.get("source_ip", "N/A")},
            {"title": "Rule Level", "value": str(alert.get("rule_level", "N/A"))},
        ]
        if triage and triage.get("escalation_required"):
            facts.append({"title": "Escalation", "value": "⚠️ Required"})
        return color, facts

    async def health(self) -> dict:
        if not self.webhook_url:
            return {"connected": False, "error": "No webhook URL configured"}
        return {"connected": True, "webhook_configured": True}
