import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Text, JSON, Column
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from shared.models.base import Base, NullableTenantMixin


class KnowledgeChunk(Base, NullableTenantMixin):
    __tablename__ = "knowledge_chunks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(255))
    chunk_text: Mapped[str] = mapped_column(Text)
    embedding = Column(JSON, nullable=True)
    extra_meta: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    token_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
