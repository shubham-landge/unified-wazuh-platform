import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from shared.models.base import Base, TenantMixin

class ApprovalRequest(Base, TenantMixin):
    __tablename__ = "approval_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    requested_by: Mapped[str] = mapped_column(String(255))
    action_type: Mapped[str] = mapped_column(String(64))
    action_params: Mapped[dict] = mapped_column(JSON)
    target_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rationale: Mapped[str] = mapped_column(Text)
    risk_level: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
