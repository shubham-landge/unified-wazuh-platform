"""Report scheduler worker — delivers scheduled reports via email/Slack/Teams."""
import asyncio
import logging
from datetime import datetime, timezone
from croniter import croniter

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select

from shared.config import settings
from shared.models.report_schedule import ReportSchedule, ReportDelivery
from shared.connectors.notify_email import EmailConnector
from shared.connectors.notify_slack import SlackConnector
from shared.connectors.notify_teams import TeamsConnector

logger = logging.getLogger(__name__)


class ReportScheduler:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client: redis.Redis | None = None

    async def start(self):
        """Main loop — check for due schedules every N seconds."""
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("Report scheduler started. Check interval: %ds", settings.schedule_check_interval_seconds)

        while True:
            try:
                await self._check_and_execute_schedules()
            except Exception as e:
                logger.error("Scheduler check failed: %s", e, exc_info=True)

            await asyncio.sleep(settings.schedule_check_interval_seconds)

    async def _check_and_execute_schedules(self):
        """Find due schedules and execute them."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(ReportSchedule).where(ReportSchedule.is_active == True)
            )
            schedules = result.scalars().all()

            now = datetime.now(timezone.utc)
            for schedule in schedules:
                if self._is_due(schedule, now):
                    logger.info("Report schedule %s is due, executing...", schedule.id)
                    await self._execute_schedule(session, schedule, now)

    @staticmethod
    def _is_due(schedule: ReportSchedule, now: datetime) -> bool:
        """Check if schedule is due based on cron expression."""
        try:
            cron = croniter(schedule.cron_expression, schedule.last_run_at or now)
            next_run = cron.get_next(datetime)
            return next_run <= now
        except Exception as e:
            logger.warning("Invalid cron expression for schedule %s: %s", schedule.id, e)
            return False

    async def _execute_schedule(
        self,
        session,
        schedule: ReportSchedule,
        now: datetime,
    ):
        """Execute a report schedule — generate report and deliver."""
        delivery = ReportDelivery(
            schedule_id=schedule.id,
            status="pending",
            delivery_method=schedule.delivery_method,
            recipient_count=len(schedule.recipients),
            started_at=now,
        )
        session.add(delivery)
        await session.flush()

        try:
            # TODO: Generate report based on schedule.report_type and parameters
            # For now, we'll just mark as success and deliver
            await self._deliver_report(schedule, delivery)
            delivery.status = "delivered"
            delivery.completed_at = datetime.now(timezone.utc)
            logger.info("Report delivered for schedule %s", schedule.id)
        except Exception as e:
            delivery.status = "failed"
            delivery.error_message = str(e)
            delivery.completed_at = datetime.now(timezone.utc)
            logger.error("Report delivery failed for schedule %s: %s", schedule.id, e)

        # Update schedule's last_run_at
        schedule.last_run_at = now
        await session.commit()

    async def _deliver_report(self, schedule: ReportSchedule, delivery: ReportDelivery):
        """Send report via the configured delivery method."""
        if schedule.delivery_method == "email":
            await self._send_email(schedule, delivery)
        elif schedule.delivery_method == "slack":
            await self._send_slack(schedule, delivery)
        elif schedule.delivery_method == "teams":
            await self._send_teams(schedule, delivery)
        else:
            raise ValueError(f"Unknown delivery method: {schedule.delivery_method}")

    async def _send_email(self, schedule: ReportSchedule, delivery: ReportDelivery):
        """Send via email."""
        if not settings.smtp_host:
            raise ValueError("SMTP not configured")

        connector = EmailConnector()
        body_html = f"""
        <h2>{schedule.name}</h2>
        <p>Report generated on {datetime.now(timezone.utc).isoformat()}</p>
        <p>Report type: {schedule.report_type}</p>
        <p>See attached for details.</p>
        """
        result = await connector.send(
            to=schedule.recipients,
            subject=f"Scheduled Report: {schedule.name}",
            body_html=body_html,
            cc=schedule.cc_recipients or None,
        )
        if not result.get("success"):
            raise Exception(result.get("error", "Email send failed"))

    async def _send_slack(self, schedule: ReportSchedule, delivery: ReportDelivery):
        """Send via Slack."""
        if not settings.slack_webhook_url:
            raise ValueError("Slack webhook not configured")

        connector = SlackConnector()
        text = f"*{schedule.name}* report generated\nType: {schedule.report_type}"
        result = await connector.send(text=text, channel=None)
        if not result.get("success"):
            raise Exception(result.get("error", "Slack send failed"))

    async def _send_teams(self, schedule: ReportSchedule, delivery: ReportDelivery):
        """Send via Teams."""
        if not settings.teams_webhook_url:
            raise ValueError("Teams webhook not configured")

        connector = TeamsConnector()
        result = await connector.send(
            title=schedule.name,
            summary=f"Report type: {schedule.report_type}\nGenerated: {datetime.now(timezone.utc).isoformat()}",
        )
        if not result.get("success"):
            raise Exception(result.get("error", "Teams send failed"))

    async def stop(self):
        if self.redis_client:
            await self.redis_client.close()
        await self.engine.dispose()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    scheduler = ReportScheduler()
    try:
        await scheduler.start()
    except KeyboardInterrupt:
        await scheduler.stop()


if __name__ == "__main__":
    asyncio.run(main())
