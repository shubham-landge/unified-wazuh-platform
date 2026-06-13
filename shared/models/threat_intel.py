import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, JSON, Text, Boolean, DECIMAL
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from shared.models.base import Base


class ThreatIntelIoc(Base):
    __tablename__ = "threat_intel_iocs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True, nullable=True)

    # IOC identity
    ioc_type: Mapped[str] = mapped_column(String(32))      # ip, domain, hash_md5, hash_sha256, url, email
    ioc_value: Mapped[str] = mapped_column(String(512), index=True)
    source: Mapped[str] = mapped_column(String(64))         # otx, misp, virustotal

    # Threat context
    threat_score: Mapped[float | None] = mapped_column(DECIMAL(5, 2), nullable=True)
    confidence: Mapped[float | None] = mapped_column(DECIMAL(3, 2), nullable=True)
    malware_families: Mapped[list | None] = mapped_column(JSON, nullable=True)
    tags: Mapped[list | None] = mapped_column(JSON, nullable=True)
    raw_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Timestamps
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AlertIocMatch(Base):
    __tablename__ = "alert_ioc_matches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    ioc_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    matched_field: Mapped[str] = mapped_column(String(64))   # source_ip, file_hash, etc.
    matched_value: Mapped[str] = mapped_column(String(512))
    threat_score: Mapped[float | None] = mapped_column(DECIMAL(5, 2), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
