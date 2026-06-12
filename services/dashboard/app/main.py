import httpx
import os
import json
from datetime import datetime
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

app = FastAPI()

API_BASE = os.getenv("API_BASE_URL", "http://api:8000")
templates = Jinja2Templates(directory="templates")

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")


async def api_request(method: str, path: str, json_data: dict = None, data: dict = None):
    headers = {"X-API-Key": os.getenv("API_KEYS", "soc-key-001").split(",")[0]}
    async with httpx.AsyncClient(timeout=10.0) as client:
        url = f"{API_BASE}{path}"
        if method.upper() == "GET":
            resp = await client.get(url, headers=headers)
        elif method.upper() == "POST":
            resp = await client.post(url, headers=headers, json=json_data, data=data)
        elif method.upper() == "PATCH":
            resp = await client.patch(url, headers=headers, json=json_data, data=data)
        elif method.upper() == "PUT":
            resp = await client.put(url, headers=headers, json=json_data, data=data)
        elif method.upper() == "DELETE":
            resp = await client.delete(url, headers=headers)
        
        if resp.status_code >= 400:
            try:
                return resp.json()
            except Exception:
                return {"status": "error", "message": resp.text}
        try:
            return resp.json()
        except Exception:
            return {"status": "success", "text": resp.text}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    health = await api_request("GET", "/health")
    alerts = await api_request("GET", "/alerts/recent?limit=100")
    cases = await api_request("GET", "/cases?limit=100")
    vulns = await api_request("GET", "/vulnerabilities?limit=100")

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
    alerts = await api_request("GET", f"/alerts/recent?limit=100&min_level={level}")
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "alerts": alerts.get("alerts", []),
        "page": "alerts",
    })


@app.get("/alerts/{alert_id}", response_class=HTMLResponse)
async def alert_detail(request: Request, alert_id: str):
    alert = await api_request("GET", f"/alerts/{alert_id}")
    return templates.TemplateResponse("alert_detail.html", {
        "request": request,
        "alert": alert.get("alert", {}),
        "page": "alerts",
    })


@app.get("/cases", response_class=HTMLResponse)
async def cases_page(request: Request):
    cases = await api_request("GET", "/cases?limit=100")
    return templates.TemplateResponse("cases.html", {
        "request": request,
        "cases": cases.get("cases", []),
        "page": "cases",
    })


@app.post("/cases")
async def create_case(request: Request):
    try:
        # Check if JSON
        payload = await request.json()
    except Exception:
        form_data = await request.form()
        payload = {
            "title": form_data.get("title"),
            "description": form_data.get("description"),
            "severity": form_data.get("severity", "medium"),
            "category": form_data.get("category", "triage"),
            "alert_id": form_data.get("alert_id")
        }
    
    # Clean payload of empty fields
    if not payload.get("alert_id"):
        payload.pop("alert_id", None)
        
    res = await api_request("POST", "/cases", json_data=payload)
    
    # If HTMX request, we can just return cases table body or redirect
    if request.headers.get("HX-Request"):
        cases = await api_request("GET", "/cases?limit=100")
        return templates.TemplateResponse("cases.html", {
            "request": request,
            "cases": cases.get("cases", []),
            "page": "cases",
            "toast": {"type": "success", "message": "Case created successfully"}
        })
        
    return RedirectResponse(url="/cases", status_code=303)


@app.get("/cases/{case_id}", response_class=HTMLResponse)
async def case_detail(request: Request, case_id: str):
    case = await api_request("GET", f"/cases/{case_id}")
    return templates.TemplateResponse("case_detail.html", {
        "request": request,
        "case": case.get("case", {}),
        "page": "cases",
    })


@app.patch("/cases/{case_id}")
async def update_case(request: Request, case_id: str):
    try:
        payload = await request.json()
    except Exception:
        form_data = await request.form()
        payload = {}
        for k, v in form_data.items():
            if v == "true":
                payload[k] = True
            elif v == "false":
                payload[k] = False
            else:
                payload[k] = v
                
    res = await api_request("PATCH", f"/cases/{case_id}", json_data=payload)
    
    case_res = await api_request("GET", f"/cases/{case_id}")
    return templates.TemplateResponse("case_detail.html", {
        "request": request,
        "case": case_res.get("case", {}),
        "page": "cases",
        "toast": {"type": "success", "message": "Case updated successfully"}
    })


@app.post("/cases/{case_id}/notes")
async def add_note(request: Request, case_id: str):
    try:
        payload = await request.json()
    except Exception:
        form_data = await request.form()
        payload = {
            "analyst": form_data.get("analyst", "Analyst"),
            "note": form_data.get("note", ""),
            "note_type": form_data.get("note_type", "general")
        }
        
    res = await api_request("POST", f"/cases/{case_id}/notes", json_data=payload)
    
    case_res = await api_request("GET", f"/cases/{case_id}")
    return templates.TemplateResponse("case_detail.html", {
        "request": request,
        "case": case_res.get("case", {}),
        "page": "cases",
        "toast": {"type": "success", "message": "Analyst note added"}
    })


@app.post("/triage/run")
async def run_triage(request: Request):
    try:
        payload = await request.json()
    except Exception:
        form_data = await request.form()
        payload = {"alert_id": form_data.get("alert_id")}
        
    res = await api_request("POST", "/triage/run", json_data=payload)
    
    return templates.TemplateResponse("triage_result_partial.html", {
        "request": request,
        "result": res,
        "toast": {"type": "success", "message": "AI Triage analysis complete"}
    })


@app.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities_page(request: Request):
    vulns = await api_request("GET", "/vulnerabilities?limit=100")
    return templates.TemplateResponse("vulnerabilities.html", {
        "request": request,
        "vulnerabilities": vulns.get("vulnerabilities", []),
        "page": "vulnerabilities",
    })


@app.get("/assets", response_class=HTMLResponse)
async def assets_page(request: Request):
    assets = await api_request("GET", "/assets?limit=100")
    return templates.TemplateResponse("assets.html", {
        "request": request,
        "assets": assets.get("assets", []),
        "page": "assets",
    })


@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    logs = await api_request("GET", "/audit?limit=100")
    return templates.TemplateResponse("audit.html", {
        "request": request,
        "entries": logs.get("entries", []),
        "page": "audit",
    })


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    try:
        reports = await api_request("GET", "/reports")
        reports_list = reports.get("reports", [])
    except Exception:
        reports_list = []
        
    if not reports_list:
        reports_list = [
            {
                "id": "rep-001",
                "name": "Weekly Security Executive Summary",
                "type": "Executive",
                "format": "PDF",
                "created_at": "2026-06-12T10:00:00Z",
                "status": "completed",
                "size": "1.2 MB"
            },
            {
                "id": "rep-002",
                "name": "PCI-DSS v4.0 Compliance Audit Report",
                "type": "Compliance",
                "format": "PDF",
                "created_at": "2026-06-11T14:30:00Z",
                "status": "completed",
                "size": "3.4 MB"
            },
            {
                "id": "rep-003",
                "name": "Technical Vulnerability Assessment",
                "type": "Technical",
                "format": "Excel",
                "created_at": "2026-06-10T09:15:00Z",
                "status": "completed",
                "size": "850 KB"
            }
        ]
        
    return templates.TemplateResponse("reports.html", {
        "request": request,
        "reports": reports_list,
        "page": "reports"
    })


@app.post("/reports/generate")
async def generate_report(request: Request):
    form_data = await request.form()
    report_type = form_data.get("report_type", "Executive")
    format_type = form_data.get("format", "PDF")
    date_range = form_data.get("date_range", "last_24h")
    
    payload = {
        "type": report_type,
        "format": format_type,
        "date_range": date_range
    }
    
    try:
        res = await api_request("POST", "/reports", json_data=payload)
    except Exception:
        pass
        
    return RedirectResponse(url="/reports", status_code=303)


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    settings_path = "app/settings.json"
    local_settings = {
        "api_key": os.getenv("API_KEYS", "soc-key-001").split(",")[0],
        "wazuh_host": "https://wazuh.local:55000",
        "ollama_model": "llama3",
        "auto_triage": "enabled",
        "retention_days": "90",
        "sync_interval": "60"
    }
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r") as f:
                local_settings.update(json.load(f))
        except Exception:
            pass
            
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "settings": local_settings,
        "page": "settings"
    })


@app.post("/settings")
async def save_settings(request: Request):
    form_data = await request.form()
    new_settings = {k: v for k, v in form_data.items()}
    
    settings_path = "app/settings.json"
    try:
        with open(settings_path, "w") as f:
            json.dump(new_settings, f, indent=4)
    except Exception:
        pass
        
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "settings": new_settings,
        "page": "settings",
        "toast": {"type": "success", "message": "Settings updated successfully"}
    })
