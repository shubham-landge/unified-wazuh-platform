import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, JSON, Text, BigInteger
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from shared.models.base import Base, TenantMixin


class Alert(Base, TenantMixin):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wazuh_alert_id: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    rule_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_groups: Mapped[list | None] = mapped_column(ARRAY(String), default=list)
    rule_firedtimes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    user_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    log_source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_alert_redacted: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    alert_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
