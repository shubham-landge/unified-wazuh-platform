import uuid
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from services.worker.app.report_scheduler import ReportScheduler
from shared.models.report_schedule import ReportSchedule, ReportDelivery


def _patch_file_io():
    return patch("services.worker.app.report_scheduler.Path", MagicMock())


@pytest.mark.asyncio
async def test_last_run_at_not_updated_on_delivery_failure():
    scheduler = ReportScheduler()
    scheduler.engine = MagicMock()

    schedule = ReportSchedule(
        id=uuid.uuid4(),
        name="Daily SOC",
        report_type="executive",
        cron_expression="0 0 * * *",
        parameters={"format": "PDF", "date_range": "last_24h"},
        delivery_method="email",
        recipients=["soc@example.com"],
    )
    schedule.last_run_at = None

    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()

    delivery = ReportDelivery(schedule_id=schedule.id, status="pending", delivery_method="email", recipient_count=1, started_at=datetime.now(timezone.utc))

    # Simulate failure during report delivery
    with _patch_file_io():
        with patch.object(scheduler, "_deliver_report", side_effect=RuntimeError("SMTP down")):
            with patch("services.worker.app.report_scheduler.ReportGenerator") as MockGenerator:
                generator = MockGenerator.return_value
                generator.generate_executive_summary = AsyncMock(return_value="<html>exec</html>")
                with patch("services.worker.app.report_scheduler.asyncio.get_event_loop") as mock_loop:
                    loop = MagicMock()
                    loop.run_in_executor = AsyncMock(return_value=b"pdfbytes")
                    mock_loop.return_value = loop
                    await scheduler._execute_schedule(session, schedule, datetime.now(timezone.utc))

    assert schedule.last_run_at is None
    session.commit.assert_awaited()


@pytest.mark.asyncio
async def test_last_run_at_updated_on_delivery_success():
    scheduler = ReportScheduler()
    scheduler.engine = MagicMock()

    schedule = ReportSchedule(
        id=uuid.uuid4(),
        name="Daily SOC",
        report_type="executive",
        cron_expression="0 0 * * *",
        parameters={"format": "PDF", "date_range": "last_24h"},
        delivery_method="email",
        recipients=["soc@example.com"],
    )
    schedule.last_run_at = None

    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()

    now = datetime.now(timezone.utc)

    with _patch_file_io():
        with patch.object(scheduler, "_deliver_report", return_value=None):
            with patch("services.worker.app.report_scheduler.ReportGenerator") as MockGenerator:
                generator = MockGenerator.return_value
                generator.generate_executive_summary = AsyncMock(return_value="<html>exec</html>")
                with patch("services.worker.app.report_scheduler.asyncio.get_event_loop") as mock_loop:
                    loop = MagicMock()
                    loop.run_in_executor = AsyncMock(return_value=b"pdfbytes")
                    mock_loop.return_value = loop
                    await scheduler._execute_schedule(session, schedule, now)

    assert schedule.last_run_at == now
    session.commit.assert_awaited()
