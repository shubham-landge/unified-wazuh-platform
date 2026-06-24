import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.config import settings
from app.middleware.audit import AuditMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.dashboard_access import DashboardAccessMiddleware
from app.middleware.tenant_enforce import TenantEnforcementMiddleware
from app.middleware.metering import UsageMeteringMiddleware
from app.routers import (
    health,
    alerts,
    alerts_ingest,
    auth,
    cases,
    vulnerabilities,
    assets,
    triage,
    audit,
    reports,
    notifications,
    soar,
    playbooks,
    threat_intel,
    ueba,
    users,
    compliance,
    rag,
    agents,
    ticketing,
    approvals,
    osint,
    usage,
    tenants,
    metrics,
    posture,
    wazuh_health,
)

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    yield
    logger.info(f"Shutting down {settings.app_name}")


_cors_origins = [o.strip() for o in settings.cors_allowed_origins.split(",") if o.strip()] if settings.cors_allowed_origins else []

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,  # fail-closed: empty list when no origins configured
    allow_credentials=bool(_cors_origins),  # credentials only when origins are explicit
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type", "Authorization"],
)
app.add_middleware(AuditMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(DashboardAccessMiddleware)
app.add_middleware(TenantEnforcementMiddleware)
app.add_middleware(UsageMeteringMiddleware)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(alerts_ingest.router)
app.include_router(cases.router)
app.include_router(vulnerabilities.router)
app.include_router(assets.router)
app.include_router(triage.router)
app.include_router(audit.router)
app.include_router(reports.router)
app.include_router(notifications.router)
app.include_router(soar.router)
app.include_router(playbooks.router)
app.include_router(threat_intel.router)
app.include_router(ueba.router)
app.include_router(users.router)
app.include_router(compliance.router)
app.include_router(rag.router)
app.include_router(agents.router)
app.include_router(ticketing.router)
app.include_router(approvals.router)
app.include_router(osint.router)
app.include_router(usage.router)
app.include_router(tenants.router)
app.include_router(metrics.router)
app.include_router(posture.router)
app.include_router(wazuh_health.router)
