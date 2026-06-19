import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Integer, Float, Boolean, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from shared.models.base import Base, NullableTenantMixin


class WazuhHealthSnapshot(Base, NullableTenantMixin):
    """A point-in-time snapshot of the Wazuh environment + our own pipeline.

    Written by the wazuh_health_worker on each poll. Powers the "Wazuh
    Environment" dashboard and the Prometheus gauges, and is the substrate for
    threshold alerts (cluster red, mass agent disconnect, ingestion lag, etc.).
    """

    __tablename__ = "wazuh_health_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    manager_label: Mapped[str] = mapped_column(String(64), default="default")
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    # ── Agent connectivity ──
    agents_active: Mapped[int] = mapped_column(Integer, default=0)
    agents_disconnected: Mapped[int] = mapped_column(Integer, default=0)
    agents_never_connected: Mapped[int] = mapped_column(Integer, default=0)
    agents_pending: Mapped[int] = mapped_column(Integer, default=0)
    agents_total: Mapped[int] = mapped_column(Integer, default=0)

    # ── Manager & cluster ──
    cluster_status: Mapped[str] = mapped_column(String(24), default="unknown")
    manager_all_running: Mapped[bool] = mapped_column(Boolean, default=True)
    analysisd_eps: Mapped[float] = mapped_column(Float, default=0.0)
    analysisd_queue_pct: Mapped[float] = mapped_column(Float, default=0.0)
    events_dropped: Mapped[int] = mapped_column(Integer, default=0)

    # ── Indexer & ingestion ──
    indexer_status: Mapped[str] = mapped_column(String(16), default="unknown")
    indexer_unassigned_shards: Mapped[int] = mapped_column(Integer, default=0)
    ingestion_lag_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ── Self-monitoring (our pipeline) ──
    self_poller_lag_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    self_triage_queue_depth: Mapped[int] = mapped_column(Integer, default=0)

    # ── Overall ──
    overall_status: Mapped[str] = mapped_column(String(16), default="healthy")  # healthy|degraded|unhealthy
    issues: Mapped[list] = mapped_column(JSON, default=list)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
