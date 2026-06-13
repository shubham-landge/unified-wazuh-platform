import logging
import httpx

from shared.config import settings

logger = logging.getLogger(__name__)


class SlackConnector:
    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or settings.slack_webhook_url

    async def send(
        self,
        text: str,
        blocks: list | None = None,
        channel: str | None = None,
    ) -> dict:
        if not self.webhook_url:
            return {"success": False, "error": "Slack webhook URL not configured"}

        payload: dict = {"text": text}
        if blocks:
            payload["blocks"] = blocks
        if channel:
            payload["channel"] = channel

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(self.webhook_url, json=payload)
                resp.raise_for_status()
            logger.info("Slack message sent | text_preview=%s", text[:80])
            return {"success": True}
        except Exception as e:
            logger.error("Slack send failed: %s", e)
            return {"success": False, "error": str(e)}

    def build_alert_blocks(self, alert: dict, triage: dict | None = None) -> list:
        severity = triage.get("severity", "unknown") if triage else "unknown"
        color_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        icon = color_map.get(severity, "⚪")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{icon} SOC Alert: {alert.get('rule_description', 'Unknown')[:75]}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Agent:*\n{alert.get('agent_name', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n{alert.get('source_ip', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Rule Level:*\n{alert.get('rule_level', 'N/A')}"},
                ],
            },
        ]
        if triage and triage.get("summary"):
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*AI Summary:*\n{triage['summary']}"},
            })
        return blocks

    async def health(self) -> dict:
        if not self.webhook_url:
            return {"connected": False, "error": "No webhook URL configured"}
        return {"connected": True, "webhook_configured": True}
