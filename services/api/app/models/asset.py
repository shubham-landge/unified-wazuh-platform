import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, JSON, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from app.models.base import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    agent_id: Mapped[str] = mapped_column(String(255))
    agent_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    os_platform: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_major: Mapped[int | None] = mapped_column(Integer, nullable=True)
    os_minor: Mapped[int | None] = mapped_column(Integer, nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    groups: Mapped[list | None] = mapped_column(ARRAY(String), default=list)
    labels: Mapped[dict | None] = mapped_column(JSON, default=dict)
    node_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    date_add: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    criticality: Mapped[int] = mapped_column(Integer, default=5)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
