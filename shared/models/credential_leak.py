import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, JSON, Text, Boolean, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from shared.models.base import Base, TenantMixin


class CredentialLeak(Base, TenantMixin):
    """Credential or domain breach discovered via HIBP or similar feed."""

    __tablename__ = "credential_leaks"
    __table_args__ = (Index("ix_credential_leaks_tenant_created", "tenant_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )

    # The monitored identifier: email address or domain name.
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(
        String(32), default="email"
    )  # "email" | "domain"

    breach_name: Mapped[str] = mapped_column(String(255), nullable=False)
    breach_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    compromised_data: Mapped[list[str]] = mapped_column(
        JSON, default=list
    )
    breach_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    acknowledged_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    source: Mapped[str] = mapped_column(String(64), default="hibp")
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
