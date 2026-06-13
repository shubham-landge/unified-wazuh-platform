import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.config import settings
from app.middleware.audit import AuditMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.dashboard_access import DashboardAccessMiddleware
from app.middleware.tenant_enforce import TenantEnforcementMiddleware
from app.routers import (
    health,
    alerts,
    auth,
    cases,
    vulnerabilities,
    assets,
    triage,
    audit,
    reports,
    notifications,
    soar,
    threat_intel,
    ueba,
    users,
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
    allow_origins=_cors_origins or ["*"],
    allow_credentials=bool(_cors_origins),  # credentials only when origins are explicit
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type", "Authorization"],
)
app.add_middleware(AuditMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(DashboardAccessMiddleware)
app.add_middleware(TenantEnforcementMiddleware)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(cases.router)
app.include_router(vulnerabilities.router)
app.include_router(assets.router)
app.include_router(triage.router)
app.include_router(audit.router)
app.include_router(reports.router)
app.include_router(notifications.router)
app.include_router(soar.router)
app.include_router(threat_intel.router)
app.include_router(ueba.router)
app.include_router(users.router)
