import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Boolean, JSON, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from shared.models.base import Base


class ReportSchedule(Base):
    """Scheduled report delivery configuration."""
    __tablename__ = "report_schedules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Report type — "monthly_soc_report", "vulnerability_report", "compliance_report", etc
    report_type: Mapped[str] = mapped_column(String(64))

    # Cron-like schedule: "0 9 * * 1" (every Monday 9am), "0 8 1 * *" (first of month 8am)
    cron_expression: Mapped[str] = mapped_column(String(255))

    # Report parameters (filters, options, etc) — JSON dict
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)

    # Delivery
    delivery_method: Mapped[str] = mapped_column(String(32), default="email")  # email, slack, teams, etc
    recipients: Mapped[list[str]] = mapped_column(JSON, default=list)  # emails or user IDs
    cc_recipients: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Execution history
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_status: Mapped[str | None] = mapped_column(String(32), nullable=True)  # success, failed
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ReportDelivery(Base):
    """Log of each report delivery."""
    __tablename__ = "report_deliveries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    schedule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    report_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending, delivered, failed
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    recipient_count: Mapped[int] = mapped_column(Integer, default=0)
    delivery_method: Mapped[str] = mapped_column(String(32))

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
