import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, JSON, Text, Boolean, DECIMAL, Float
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from shared.models.base import Base


class UebaBaseline(Base):
    """Rolling statistical baseline for a (entity_type, entity_value, metric) triplet."""
    __tablename__ = "ueba_baselines"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True, nullable=True)

    entity_type: Mapped[str] = mapped_column(String(32), index=True)   # user, host, process
    entity_value: Mapped[str] = mapped_column(String(255), index=True)
    metric: Mapped[str] = mapped_column(String(64), index=True)         # alert_count, login_count, etc.
    window_hours: Mapped[int] = mapped_column(Integer, default=24)

    # Welford online statistics
    n: Mapped[int] = mapped_column(Integer, default=0)
    mean: Mapped[float] = mapped_column(Float, default=0.0)
    m2: Mapped[float] = mapped_column(Float, default=0.0)   # sum of squared deviations

    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class UebaAnomaly(Base):
    __tablename__ = "ueba_anomalies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True, nullable=True)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    entity_type: Mapped[str] = mapped_column(String(32))
    entity_value: Mapped[str] = mapped_column(String(255))
    metric: Mapped[str] = mapped_column(String(64))

    observed_value: Mapped[float] = mapped_column(Float)
    baseline_mean: Mapped[float] = mapped_column(Float)
    baseline_stddev: Mapped[float] = mapped_column(Float)
    z_score: Mapped[float] = mapped_column(Float)

    severity: Mapped[str] = mapped_column(String(16), default="medium")
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
