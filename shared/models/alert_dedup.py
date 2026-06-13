import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from shared.models.base import Base, NullableTenantMixin


class AlertIncident(Base, NullableTenantMixin):
    """Deduplicated incident grouping related alerts."""
    __tablename__ = "alert_incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Grouping key: deterministic hash of (rule_id, agent_id, source_ip)
    # Used to detect duplicates within the correlation window
    group_key: Mapped[str] = mapped_column(String(255), index=True)

    rule_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Count of alerts in this incident
    alert_count: Mapped[int] = mapped_column(Integer, default=1)

    # Severity from first (or most severe) alert in the group
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open, investigating, closed

    # Time window for correlation
    first_alert_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_alert_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    correlation_window_minutes: Mapped[int] = mapped_column(Integer, default=120)

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
