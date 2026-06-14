"""Report scheduler worker — delivers scheduled reports via email/Slack/Teams."""
import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from croniter import croniter

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select

from shared.config import settings
from shared.models.report_schedule import ReportSchedule, ReportDelivery
from shared.models.report import Report
from shared.report_generator import ReportGenerator
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
        delivery = ReportDelivery(
            schedule_id=schedule.id,
            status="pending",
            delivery_method=schedule.delivery_method,
            recipient_count=len(schedule.recipients),
            started_at=now,
        )
        session.add(delivery)
        await session.flush()

        report_format = schedule.parameters.get("format", "PDF").upper()
        report_file_path = None
        report_file_size = None

        try:
            generator = ReportGenerator(session)
            report_type = schedule.report_type
            params = schedule.parameters or {}

            if report_type in ("vulnerability", "technical"):
                html = await generator.generate_vulnerability_report(
                    params.get("date_range", "last_30d"),
                    params.get("filters", {}),
                )
            elif report_type == "case":
                case_id = params.get("case_id")
                if not case_id:
                    raise ValueError("case_id is required for case reports")
                html = await generator.generate_case_report(case_id)
            elif report_type == "executive":
                html = await generator.generate_executive_summary(
                    params.get("date_range", "last_30d")
                )
            elif report_type == "compliance":
                html = await generator.generate_compliance_report(
                    framework_id=params.get("framework_id")
                )
            else:
                html = await generator.generate_monthly_soc_report(now.month, now.year)

            storage = Path(settings.reports_storage_path)
            storage.mkdir(parents=True, exist_ok=True)
            suffix = "xlsx" if report_format == "EXCEL" else report_format.lower()
            file_path = storage / f"{uuid.uuid4()}.{suffix}"

            if report_format == "PDF":
                content = await asyncio.get_event_loop().run_in_executor(None, generator.html_to_pdf, html)
            elif report_format == "JSON":
                import json
                content = json.dumps({"html": html}).encode("utf-8")
            else:
                content = html.encode("utf-8")

            file_path.write_bytes(content)
            report_file_path = str(file_path)
            report_file_size = len(content)

            report_record = Report(
                tenant_id=schedule.tenant_id,
                name=schedule.name,
                report_type=report_type,
                format=report_format,
                parameters=params,
                file_path=report_file_path,
                file_size=report_file_size,
                status="completed",
                created_by="scheduler",
                completed_at=datetime.now(timezone.utc),
                expires_at=now + timedelta(days=settings.report_retention_days),
            )
            session.add(report_record)
            await session.flush()
            delivery.report_id = report_record.id

            await self._deliver_report(schedule, delivery, report_file_path, report_format)
            delivery.status = "delivered"
            delivery.completed_at = datetime.now(timezone.utc)
            # Only update last_run_at on successful delivery so the schedule will retry on failure
            schedule.last_run_at = now
            logger.info("Report delivered for schedule %s", schedule.id)
        except Exception as e:
            delivery.status = "failed"
            delivery.error_message = str(e)
            delivery.completed_at = datetime.now(timezone.utc)
            logger.error("Report delivery failed for schedule %s: %s", schedule.id, e)

        await session.commit()

    async def _deliver_report(
        self,
        schedule: ReportSchedule,
        delivery: ReportDelivery,
        report_path: str | None = None,
        report_format: str = "PDF",
    ):
        """Send report via the configured delivery method."""
        if schedule.delivery_method == "email":
            await self._send_email(schedule, delivery, report_path, report_format)
        elif schedule.delivery_method == "slack":
            await self._send_slack(schedule, delivery, report_path)
        elif schedule.delivery_method == "teams":
            await self._send_teams(schedule, delivery, report_path)
        else:
            raise ValueError(f"Unknown delivery method: {schedule.delivery_method}")

    async def _send_email(
        self,
        schedule: ReportSchedule,
        delivery: ReportDelivery,
        report_path: str | None = None,
        report_format: str = "PDF",
    ):
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

        attachments = []
        if report_path and Path(report_path).is_file():
            suffix = Path(report_path).suffix.lstrip(".")
            mime_types = {
                "pdf": "application/pdf",
                "html": "text/html",
                "json": "application/json",
                "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            }
            mime_type = mime_types.get(suffix, "application/octet-stream")
            filename = f"{schedule.name}.{suffix}"
            attachments.append({
                "filename": filename,
                "content": Path(report_path).read_bytes(),
                "mime_type": mime_type,
            })

        result = await connector.send(
            to=schedule.recipients,
            subject=f"Scheduled Report: {schedule.name}",
            body_html=body_html,
            cc=schedule.cc_recipients or None,
            attachments=attachments,
        )
        if not result.get("success"):
            raise Exception(result.get("error", "Email send failed"))

    async def _send_slack(
        self,
        schedule: ReportSchedule,
        delivery: ReportDelivery,
        report_path: str | None = None,
    ):
        """Send via Slack."""
        if not settings.slack_webhook_url:
            raise ValueError("Slack webhook not configured")

        connector = SlackConnector()
        text = (
            f"*{schedule.name}* report generated\n"
            f"Type: {schedule.report_type}\n"
            f"Generated: {datetime.now(timezone.utc).isoformat()}"
        )
        if report_path:
            text += f"\nFile: {report_path}"
        result = await connector.send(text=text, channel=None)
        if not result.get("success"):
            raise Exception(result.get("error", "Slack send failed"))

    async def _send_teams(
        self,
        schedule: ReportSchedule,
        delivery: ReportDelivery,
        report_path: str | None = None,
    ):
        """Send via Teams."""
        if not settings.teams_webhook_url:
            raise ValueError("Teams webhook not configured")

        summary = (
            f"Report type: {schedule.report_type}\n"
            f"Generated: {datetime.now(timezone.utc).isoformat()}"
        )
        if report_path:
            summary += f"\nFile: {report_path}"
        connector = TeamsConnector()
        result = await connector.send(
            title=schedule.name,
            summary=summary,
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
