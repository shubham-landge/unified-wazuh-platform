import httpx
import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

app = FastAPI()

API_BASE = os.getenv("API_BASE_URL", "http://api:8000")
templates = Jinja2Templates(directory="templates")


async def api_get(path: str):
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{API_BASE}{path}",
            headers={"X-API-Key": os.getenv("API_KEYS", "soc-key-001").split(",")[0]},
        )
        return resp.json()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    health = await api_get("/health")
    alerts = await api_get("/alerts/recent?limit=10")
    cases = await api_get("/cases?limit=10")
    vulns = await api_get("/vulnerabilities?limit=10")

    return templates.TemplateResponse("index.html", {
        "request": request,
        "health": health,
        "alerts": alerts.get("alerts", []),
        "cases": cases.get("cases", []),
        "vulnerabilities": vulns.get("vulnerabilities", []),
        "page": "overview",
    })


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request, level: int = 0):
    alerts = await api_get(f"/alerts/recent?limit=100&min_level={level}")
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "alerts": alerts.get("alerts", []),
        "page": "alerts",
    })


@app.get("/alerts/{alert_id}", response_class=HTMLResponse)
async def alert_detail(request: Request, alert_id: str):
    alert = await api_get(f"/alerts/{alert_id}")
    return templates.TemplateResponse("alert_detail.html", {
        "request": request,
        "alert": alert.get("alert", {}),
        "page": "alerts",
    })


@app.get("/cases", response_class=HTMLResponse)
async def cases_page(request: Request):
    cases = await api_get("/cases?limit=100")
    return templates.TemplateResponse("cases.html", {
        "request": request,
        "cases": cases.get("cases", []),
        "page": "cases",
    })


@app.get("/cases/{case_id}", response_class=HTMLResponse)
async def case_detail(request: Request, case_id: str):
    case = await api_get(f"/cases/{case_id}")
    return templates.TemplateResponse("case_detail.html", {
        "request": request,
        "case": case.get("case", {}),
        "page": "cases",
    })


@app.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities_page(request: Request):
    vulns = await api_get("/vulnerabilities?limit=100")
    return templates.TemplateResponse("vulnerabilities.html", {
        "request": request,
        "vulnerabilities": vulns.get("vulnerabilities", []),
        "page": "vulnerabilities",
    })


@app.get("/assets", response_class=HTMLResponse)
async def assets_page(request: Request):
    assets = await api_get("/assets?limit=100")
    return templates.TemplateResponse("assets.html", {
        "request": request,
        "assets": assets.get("assets", []),
        "page": "assets",
    })


@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    logs = await api_get("/audit?limit=100")
    return templates.TemplateResponse("audit.html", {
        "request": request,
        "entries": logs.get("entries", []),
        "page": "audit",
    })
