import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.config import settings
from app.middleware.audit import AuditMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.dashboard_access import DashboardAccessMiddleware
from app.routers import health, alerts, cases, vulnerabilities, assets, triage, audit

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


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(AuditMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(DashboardAccessMiddleware)

app.include_router(health.router)
app.include_router(alerts.router)
app.include_router(cases.router)
app.include_router(vulnerabilities.router)
app.include_router(assets.router)
app.include_router(triage.router)
app.include_router(audit.router)
