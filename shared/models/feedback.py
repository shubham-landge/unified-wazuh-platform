import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Text, Boolean, DECIMAL, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from shared.models.base import Base, NullableTenantMixin


class UserFeedback(Base, NullableTenantMixin):
    __tablename__ = "user_feedback"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    triage_result_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("ai_triage_results.id"), index=True)

    rating: Mapped[int] = mapped_column(Integer)  # 1-5
    category_correct: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    severity_correct: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    correction_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    corrected_category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    corrected_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    corrected_confidence: Mapped[float | None] = mapped_column(DECIMAL(3,2), nullable=True)

    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
