import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Text, Boolean, DECIMAL, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from shared.models.base import Base


class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(32), default="1.0")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_controls: Mapped[int] = mapped_column(Integer, default=0)
    compliant_controls: Mapped[int] = mapped_column(Integer, default=0)
    score: Mapped[float] = mapped_column(DECIMAL(5,2), default=0.00)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    controls: Mapped[list["ComplianceControl"]] = relationship(back_populates="framework", cascade="all, delete-orphan")


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("compliance_frameworks.id"))
    control_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    framework: Mapped["ComplianceFramework"] = relationship(back_populates="controls")
    mappings: Mapped[list["ComplianceMapping"]] = relationship(back_populates="control", cascade="all, delete-orphan")
    exceptions: Mapped[list["ComplianceException"]] = relationship(back_populates="control", cascade="all, delete-orphan")


class ComplianceMapping(Base):
    __tablename__ = "compliance_mappings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    control_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("compliance_controls.id"))
    rule_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_level_min: Mapped[int] = mapped_column(Integer, default=0)
    cve_pattern: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    control: Mapped["ComplianceControl"] = relationship(back_populates="mappings")


class ComplianceException(Base):
    __tablename__ = "compliance_exceptions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    control_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("compliance_controls.id"))
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    reason: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    duration_days: Mapped[int] = mapped_column(Integer, default=30)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    control: Mapped["ComplianceControl"] = relationship(back_populates="exceptions")
