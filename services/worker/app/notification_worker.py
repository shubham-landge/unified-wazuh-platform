import asyncio
import json
import logging
import redis.asyncio as redis

from shared.config import settings
from shared.connectors.notify_email import EmailConnector
from shared.connectors.notify_slack import SlackConnector
from shared.connectors.notify_teams import TeamsConnector
from shared.connectors.notify_pagerduty import PagerDutyConnector

logger = logging.getLogger(__name__)

# Queue name for incoming notification jobs; DLQ for failed ones
NOTIFY_QUEUE = "notification_queue"
NOTIFY_DLQ = "notification_dlq"


class NotificationWorker:
    def __init__(self):
        self.redis_client: redis.Redis | None = None
        self._connectors = {
            "email":     EmailConnector(),
            "slack":     SlackConnector(),
            "teams":     TeamsConnector(),
            "pagerduty": PagerDutyConnector(),
        }

    async def start(self):
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("Notification worker started. Listening on %s", NOTIFY_QUEUE)
        while True:
            try:
                item = await self.redis_client.brpop(NOTIFY_QUEUE, timeout=5)
                if item:
                    _, raw = item
                    await self.dispatch(json.loads(raw))
            except TypeError:
                continue
            except Exception as e:
                logger.error("Notification worker error: %s", e, exc_info=True)
                await asyncio.sleep(1)

    async def dispatch(self, job: dict):
        """
        Job schema:
        {
            "channel": "slack" | "email" | "teams" | "pagerduty",
            "payload": { ... channel-specific fields ... },
            "alert": { ... alert dict for building messages ... },
            "triage": { ... triage dict, optional ... }
        }
        """
        channel = job.get("channel", "").lower()
        payload = job.get("payload", {})
        alert = job.get("alert", {})
        triage = job.get("triage")

        try:
            if channel == "slack":
                conn: SlackConnector = self._connectors["slack"]
                blocks = conn.build_alert_blocks(alert, triage) if alert else None
                result = await conn.send(
                    text=payload.get("text", alert.get("rule_description", "SOC Alert")),
                    blocks=blocks,
                    channel=payload.get("channel"),
                )

            elif channel == "email":
                conn: EmailConnector = self._connectors["email"]
                result = await conn.send(
                    to=payload["to"],
                    subject=payload.get("subject", "SOC Alert Notification"),
                    body_html=payload.get("body_html", f"<p>{alert.get('rule_description', '')}</p>"),
                    body_text=payload.get("body_text"),
                    cc=payload.get("cc"),
                )

            elif channel == "teams":
                conn: TeamsConnector = self._connectors["teams"]
                color, facts = conn.build_alert_facts(alert, triage)
                result = await conn.send(
                    title=payload.get("title", f"SOC Alert: {alert.get('rule_description', 'Unknown')[:60]}"),
                    summary=triage.get("summary", "") if triage else "",
                    facts=facts,
                    color=color,
                )

            elif channel == "pagerduty":
                conn: PagerDutyConnector = self._connectors["pagerduty"]
                severity = triage.get("severity", "medium") if triage else payload.get("severity", "error")
                result = await conn.trigger(
                    summary=payload.get("summary", alert.get("rule_description", "SOC Alert")),
                    source=alert.get("agent_name", "wazuh"),
                    severity=severity,
                    dedup_key=payload.get("dedup_key", alert.get("id")),
                    details={
                        "rule_level": alert.get("rule_level"),
                        "source_ip": alert.get("source_ip"),
                        "user": alert.get("user_name"),
                        "mitre": alert.get("mitre_technique"),
                        **(triage or {}),
                    },
                )

            else:
                logger.warning("Unknown notification channel: %s", channel)
                result = {"success": False, "error": f"Unknown channel: {channel}"}

            if not result.get("success"):
                await self._send_to_dlq(job, result.get("error", "unknown"))

        except Exception as e:
            logger.error("Notification dispatch failed [%s]: %s", channel, e, exc_info=True)
            await self._send_to_dlq(job, str(e))

    async def _send_to_dlq(self, job: dict, error: str):
        if self.redis_client:
            job["_error"] = error
            await self.redis_client.lpush(NOTIFY_DLQ, json.dumps(job))
            logger.warning("Job moved to DLQ: channel=%s error=%s", job.get("channel"), error)

    async def stop(self):
        if self.redis_client:
            await self.redis_client.close()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = NotificationWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
