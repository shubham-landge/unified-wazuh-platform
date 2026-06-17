import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Float, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from shared.models.base import Base, TenantMixin


class Entity(Base, TenantMixin):
    """Normalized entity extracted from alerts — user, host, ip, principal, etc."""
    __tablename__ = "entities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type: Mapped[str] = mapped_column(String(24))
    value: Mapped[str] = mapped_column(String(512))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    tags: Mapped[dict] = mapped_column(JSON, default=dict)


class AlertEntity(Base):
    """Links an extracted entity to the alert it came from."""
    __tablename__ = "alert_entities"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(16), default="observed", primary_key=True)


class IncidentEntity(Base):
    """Entities that define an incident's cross-domain identity."""
    __tablename__ = "incident_entities"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert_incidents.id", ondelete="CASCADE"), primary_key=True
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True
    )
