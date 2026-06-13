import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Boolean, JSON, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from shared.models.base import Base, NullableTenantMixin


class User(Base, NullableTenantMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Login identity
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)

    # Password (hashed via passlib)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # OIDC integration — if set, user can login via SSO instead of password
    oidc_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)  # "google", "okta", etc
    oidc_subject: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)

    # Profile
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(32), default="viewer")  # admin, analyst, viewer
    permissions: Mapped[list] = mapped_column(JSON, default=list)  # ["read:alerts", "write:cases", etc]
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Metadata
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# Role definitions — can be extended
ROLES = {
    "admin": {
        "permissions": [
            "read:*", "write:*", "delete:*",
            "admin:users", "admin:roles", "admin:audit",
            "admin:tenant",
        ],
        "description": "Full platform access",
    },
    "analyst": {
        "permissions": [
            "read:alerts", "read:cases", "read:vulnerabilities", "read:assets",
            "read:threat_intel", "read:ueba", "read:reports",
            "write:cases", "write:cases:assign", "write:cases:notes",
            "write:playbooks", "write:notifications",
            "read:audit",
        ],
        "description": "SOC analyst — triage, case management, playbook execution",
    },
    "viewer": {
        "permissions": [
            "read:alerts", "read:cases", "read:vulnerabilities", "read:assets",
            "read:threat_intel", "read:ueba", "read:reports",
            "read:audit",
        ],
        "description": "Read-only access",
    },
}
