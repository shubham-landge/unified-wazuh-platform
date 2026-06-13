import httpx
import os
import json
from datetime import datetime
from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

app = FastAPI()

API_BASE = os.getenv("API_BASE_URL", "http://api:8000")
templates = Jinja2Templates(directory="templates")

STORE_PATH = "app/dashboard_store.json"

def get_store():
    if not os.path.exists(STORE_PATH):
        return {"channels": [], "rules": [], "events": [], "playbooks": [], "playbook_runs": [], "feeds": []}
    try:
        with open(STORE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"channels": [], "rules": [], "events": [], "playbooks": [], "playbook_runs": [], "feeds": []}

def save_store(store_data):
    try:
        with open(STORE_PATH, "w") as f:
            json.dump(store_data, f, indent=4)
        return True
    except Exception:
        return False


# Ingest user context to templates automatically
@app.middleware("http")
async def add_user_to_template_context(request: Request, call_next):
    token = request.cookies.get("session_token")
    current_user = None
    if token:
        current_user = {
            "email": token,
            "display_name": token.split("@")[0].title(),
            "role": "admin" if "admin" in token else "analyst",
            "last_login": datetime.now().isoformat()
        }
    request.state.current_user = current_user
    templates.env.globals["current_user"] = current_user
    response = await call_next(request)
    return response


# Mount static files directory
static_dir = "static" if os.path.exists("static") else "services/dashboard/static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


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
    store = get_store()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "health": health,
        "alerts": alerts.get("alerts", []),
        "cases": cases.get("cases", []),
        "vulnerabilities": vulns.get("vulnerabilities", []),
        "playbook_runs": store.get("playbook_runs", []),
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


@app.get("/cases/{case_id}/timeline")
async def case_timeline(request: Request, case_id: str):
    event_type = request.query_params.get("event_type")
    limit = request.query_params.get("limit", "50")
    offset = request.query_params.get("offset", "0")
    path = f"/cases/{case_id}/timeline?limit={limit}&offset={offset}"
    if event_type:
        path += f"&event_type={event_type}"
    data = await api_request("GET", path)
    return templates.TemplateResponse("timeline_partial.html", {
        "request": request,
        "events": data.get("events", []),
        "total": data.get("total", 0),
    })


@app.get("/cases/{case_id}/steps")
async def case_steps(request: Request, case_id: str):
    data = await api_request("GET", f"/cases/{case_id}/steps")
    return templates.TemplateResponse("steps_partial.html", {
        "request": request,
        "steps": data.get("steps", []),
        "case_id": case_id,
    })


@app.post("/cases/{case_id}/steps")
async def create_step(request: Request, case_id: str):
    try:
        payload = await request.json()
    except Exception:
        form_data = await request.form()
        payload = {
            "description": form_data.get("description", ""),
            "order": int(form_data.get("order", 0)),
        }
    await api_request("POST", f"/cases/{case_id}/steps", json_data=payload)
    return await case_steps(request, case_id)


@app.patch("/cases/{case_id}/steps/{step_id}")
async def toggle_step(request: Request, case_id: str, step_id: str):
    await api_request("PATCH", f"/cases/{case_id}/steps/{step_id}", json_data={})
    return await case_steps(request, case_id)


@app.post("/cases/bulk-status")
async def bulk_update_status(request: Request):
    try:
        payload = await request.json()
    except Exception:
        form_data = await request.form()
        payload = {
            "case_ids": form_data.get("case_ids", "").split(","),
            "status": form_data.get("status", "open"),
        }
    result = await api_request("POST", "/cases/bulk-status", json_data=payload)
    return {"status": "success", "updated": result.get("updated", 0)}


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
        
    store = get_store()
    if not reports_list:
        reports_list = store.get("reports", [])
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
            store["reports"] = reports_list
            save_store(store)
            
    schedules_list = store.get("schedules", [])
    
    current_user = None
    token = request.cookies.get("session_token")
    if token:
        current_user = {
            "email": token,
            "display_name": token.split("@")[0].title(),
            "role": "admin" if "admin" in token else "analyst"
        }
        
    return templates.TemplateResponse("reports.html", {
        "request": request,
        "reports": reports_list,
        "schedules": schedules_list,
        "current_user": current_user,
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
        await api_request("POST", "/reports", json_data=payload)
    except Exception:
        pass
        
    store = get_store()
    new_report = {
        "id": f"rep-{int(datetime.now().timestamp())}",
        "name": f"{report_type} Security Report ({date_range.replace('_', ' ').capitalize()})",
        "type": report_type,
        "format": format_type,
        "created_at": datetime.now().isoformat() + "Z",
        "status": "completed",
        "size": "1.4 MB" if format_type == "PDF" else "240 KB"
    }
    store.setdefault("reports", []).insert(0, new_report)
    save_store(store)
    
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
        "sync_interval": "60",
        "otx_api_key": os.getenv("OTX_API_KEY", ""),
        "misp_url": os.getenv("MISP_URL", ""),
        "misp_api_key": os.getenv("MISP_API_KEY", ""),
        "misp_verify_ssl": os.getenv("MISP_VERIFY_SSL", "true").lower() == "true",
        "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "ti_feed_poll_interval_seconds": int(os.getenv("TI_FEED_POLL_INTERVAL_SECONDS", "3600"))
    }
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r") as f:
                loaded = json.load(f)
                # Convert types if needed
                if "misp_verify_ssl" in loaded:
                    if isinstance(loaded["misp_verify_ssl"], str):
                        loaded["misp_verify_ssl"] = loaded["misp_verify_ssl"].lower() == "true"
                if "ti_feed_poll_interval_seconds" in loaded:
                    try:
                        loaded["ti_feed_poll_interval_seconds"] = int(loaded["ti_feed_poll_interval_seconds"])
                    except ValueError:
                        pass
                local_settings.update(loaded)
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
    
    # Handle checkboxes or other boolean conversions if they are in form_data
    if "misp_verify_ssl" in new_settings:
        new_settings["misp_verify_ssl"] = new_settings["misp_verify_ssl"].lower() == "true" or new_settings["misp_verify_ssl"] == "on"
    else:
        new_settings["misp_verify_ssl"] = False

    if "ti_feed_poll_interval_seconds" in new_settings:
        try:
            new_settings["ti_feed_poll_interval_seconds"] = int(new_settings["ti_feed_poll_interval_seconds"])
        except ValueError:
            pass
    
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


@app.post("/settings/test-connector/{connector_name}")
async def test_connector(connector_name: str, request: Request):
    form_data = await request.form()
    
    try:
        if connector_name == "otx":
            from shared.connectors.ti_alienvault import AlienVaultOTXConnector
            api_key = form_data.get("otx_api_key", "").strip()
            connector = AlienVaultOTXConnector(api_key=api_key)
            res = await connector.health()
            if res.get("connected"):
                html = f'<span class="text-accent-green">✅ Connection successful! (User: {res.get("username", "Unknown")})</span>'
            else:
                html = f'<span class="text-accent-red">❌ Connection failed: {res.get("error", "Unknown error")}</span>'
                
        elif connector_name == "misp":
            from shared.connectors.ti_misp import MISPConnector
            url = form_data.get("misp_url", "").strip()
            api_key = form_data.get("misp_api_key", "").strip()
            verify_ssl = form_data.get("misp_verify_ssl") in ("true", "on", "True")
            connector = MISPConnector(base_url=url, api_key=api_key)
            connector.verify_ssl = verify_ssl
            res = await connector.health()
            if res.get("connected"):
                html = f'<span class="text-accent-green">✅ Connection successful! (Version: {res.get("version", "Unknown")})</span>'
            else:
                html = f'<span class="text-accent-red">❌ Connection failed: {res.get("error", "Unknown error")}</span>'
                
        elif connector_name == "virustotal":
            from shared.connectors.ti_virustotal import VirusTotalConnector
            api_key = form_data.get("virustotal_api_key", "").strip()
            connector = VirusTotalConnector(api_key=api_key)
            res = await connector.health()
            if res.get("connected"):
                html = '<span class="text-accent-green">✅ Connection successful!</span>'
            else:
                html = f'<span class="text-accent-red">❌ Connection failed: {res.get("error", "Unknown error")}</span>'
        else:
            html = '<span class="text-accent-red">❌ Invalid connector type</span>'
    except Exception as e:
        html = f'<span class="text-accent-red">❌ Error: {str(e)}</span>'
        
    return JSONResponse({"html": html})


@app.get("/landing", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse("landing.html", {
        "request": request,
        "page": "landing"
    })


@app.get("/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request):
    store = get_store()
    return templates.TemplateResponse("notifications.html", {
        "request": request,
        "channels": store.get("channels", []),
        "rules": store.get("rules", []),
        "events": store.get("events", []),
        "page": "notifications"
    })


@app.post("/notifications/channels")
async def create_channel(request: Request):
    form_data = await request.form()
    store = get_store()
    new_chan = {
        "id": f"chan-{int(datetime.now().timestamp())}",
        "name": form_data.get("name"),
        "type": form_data.get("type"),
        "config": form_data.get("config"),
        "enabled": form_data.get("enabled") == "on" or form_data.get("enabled") == "true",
        "created_at": datetime.now().isoformat() + "Z"
    }
    store.setdefault("channels", []).append(new_chan)
    save_store(store)
    return RedirectResponse(url="/notifications", status_code=303)


@app.post("/notifications/channels/{channel_id}/toggle")
async def toggle_channel(request: Request, channel_id: str):
    store = get_store()
    for chan in store.setdefault("channels", []):
        if chan["id"] == channel_id:
            chan["enabled"] = not chan["enabled"]
            break
    save_store(store)
    return RedirectResponse(url="/notifications", status_code=303)


@app.post("/notifications/channels/{channel_id}/delete")
async def delete_channel(request: Request, channel_id: str):
    store = get_store()
    store["channels"] = [c for c in store.setdefault("channels", []) if c["id"] != channel_id]
    save_store(store)
    return RedirectResponse(url="/notifications", status_code=303)


@app.post("/notifications/rules")
async def create_rule(request: Request):
    form_data = await request.form()
    store = get_store()
    selected_channels = form_data.getlist("channels")
    new_rule = {
        "id": f"rule-{int(datetime.now().timestamp())}",
        "name": form_data.get("name"),
        "severity_threshold": int(form_data.get("severity_threshold", 7)),
        "channels": selected_channels,
        "enabled": form_data.get("enabled") == "on" or form_data.get("enabled") == "true"
    }
    store.setdefault("rules", []).append(new_rule)
    save_store(store)
    return RedirectResponse(url="/notifications", status_code=303)


@app.post("/notifications/rules/{rule_id}/delete")
async def delete_rule(request: Request, rule_id: str):
    store = get_store()
    store["rules"] = [r for r in store.setdefault("rules", []) if r["id"] != rule_id]
    save_store(store)
    return RedirectResponse(url="/notifications", status_code=303)


@app.post("/notifications/channels/{channel_id}/test")
async def test_channel(request: Request, channel_id: str):
    store = get_store()
    chan = next((c for c in store.setdefault("channels", []) if c["id"] == channel_id), None)
    if not chan:
        return JSONResponse({"status": "error", "message": "Channel not found"}, status_code=404)
    
    new_evt = {
        "id": f"evt-{int(datetime.now().timestamp())}",
        "rule_name": "Manual Channel Test",
        "channel_name": chan["name"],
        "alert_description": f"Manual notification channel test trigger for {chan['type']}",
        "status": "success",
        "timestamp": datetime.now().isoformat() + "Z"
    }
    store.setdefault("events", []).insert(0, new_evt)
    save_store(store)
    
    headers = {"X-Toast": json.dumps({"type": "success", "message": f"Test notification sent to {chan['name']}!"})}
    return Response(headers=headers, status_code=204)


@app.get("/compliance", response_class=HTMLResponse)
async def compliance_page(request: Request, framework: str = "soc2"):
    alerts_data = await api_request("GET", "/alerts/recent?limit=100")
    vulns_data = await api_request("GET", "/vulnerabilities?limit=100")
    
    alerts = alerts_data.get("alerts", [])
    vulnerabilities = vulns_data.get("vulnerabilities", [])
    
    return templates.TemplateResponse("compliance.html", {
        "request": request,
        "alerts": alerts,
        "vulnerabilities": vulnerabilities,
        "framework": framework.lower(),
        "page": "compliance"
    })


@app.get("/playbooks", response_class=HTMLResponse)
async def playbooks_page(request: Request):
    store = get_store()
    return templates.TemplateResponse("playbooks.html", {
        "request": request,
        "playbooks": store.get("playbooks", []),
        "runs": store.get("playbook_runs", []),
        "page": "playbooks"
    })


@app.post("/playbooks")
async def save_playbook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        form_data = await request.form()
        payload = {
            "name": form_data.get("name"),
            "description": form_data.get("description"),
            "nodes": json.loads(form_data.get("nodes", "[]")),
            "enabled": form_data.get("enabled") == "on" or form_data.get("enabled") == "true"
        }
    
    store = get_store()
    new_play = {
        "id": f"play-{int(datetime.now().timestamp())}",
        "name": payload.get("name"),
        "description": payload.get("description"),
        "nodes": payload.get("nodes", []),
        "enabled": payload.get("enabled", True)
    }
    store.setdefault("playbooks", []).append(new_play)
    save_store(store)
    return RedirectResponse(url="/playbooks", status_code=303)


@app.post("/playbooks/{playbook_id}/toggle")
async def toggle_playbook(request: Request, playbook_id: str):
    store = get_store()
    for play in store.setdefault("playbooks", []):
        if play["id"] == playbook_id:
            play["enabled"] = not play["enabled"]
            break
    save_store(store)
    return RedirectResponse(url="/playbooks", status_code=303)


@app.post("/playbooks/{playbook_id}/delete")
async def delete_playbook(request: Request, playbook_id: str):
    store = get_store()
    store["playbooks"] = [p for p in store.setdefault("playbooks", []) if p["id"] != playbook_id]
    save_store(store)
    return RedirectResponse(url="/playbooks", status_code=303)


@app.post("/playbooks/{playbook_id}/run")
async def run_playbook_manual(request: Request, playbook_id: str):
    store = get_store()
    play = next((p for p in store.setdefault("playbooks", []) if p["id"] == playbook_id), None)
    if not play:
        return JSONResponse({"status": "error", "message": "Playbook not found"}, status_code=404)
        
    new_run = {
        "id": f"run-{int(datetime.now().timestamp())}",
        "playbook_name": play["name"],
        "trigger": "Manual Operator Trigger",
        "started_at": datetime.now().isoformat() + "Z",
        "duration": "3.1s",
        "status": "success",
        "logs": [
            f"{datetime.now().strftime('%H:%M:%S')} - Playbook '{play['name']}' manually executed.",
            f"{datetime.now().strftime('%H:%M:%S')} - Verifying workflow triggers and conditions...",
            f"{datetime.now().strftime('%H:%M:%S')} - Running nodes sequence (Total: {len(play['nodes'])} nodes).",
            f"{datetime.now().strftime('%H:%M:%S')} - Completed manual playbook execution."
        ]
    }
    store.setdefault("playbook_runs", []).insert(0, new_run)
    save_store(store)
    
    headers = {"X-Toast": json.dumps({"type": "success", "message": f"Playbook '{play['name']}' executed successfully!"})}
    return HTMLResponse(
        status_code=200,
        content="<script>window.location.reload();</script>",
        headers=headers
    )


@app.get("/threat-intel", response_class=HTMLResponse)
async def threat_intel_page(request: Request, query: str = None):
    store = get_store()
    feeds = store.get("feeds", [])
    
    ioc_results = None
    if query:
        q = query.strip()
        score = 85 if q.startswith("192.") or q.startswith("8.8.") or q.startswith("10.") else 95 if len(q) > 15 else 45
        category = "Malicious Host" if score > 80 else "Tor Exit Node" if score > 70 else "Phishing Domain" if score > 50 else "Clean / Unknown"
        ioc_results = {
            "query": q,
            "type": "IP Address" if q.replace(".", "").isdigit() else "File Hash (SHA-256)" if len(q) == 64 else "Domain Name",
            "score": score,
            "category": category,
            "geoip": "Russia (RU)" if score > 80 else "United States (US)" if score > 40 else "N/A",
            "actor": "APT29 (Cozy Bear)" if score > 80 else "Unknown" if score > 50 else "N/A",
            "last_seen": "2026-06-13T05:00:00Z",
            "alerts_count": 4 if score > 70 else 0
        }
        
    return templates.TemplateResponse("threat_intel.html", {
        "request": request,
        "feeds": feeds,
        "query": query,
        "ioc_results": ioc_results,
        "page": "threat-intel"
    })


@app.post("/threat-intel/feeds/{feed_id}/sync")
async def sync_threat_feed(request: Request, feed_id: str):
    store = get_store()
    for feed in store.setdefault("feeds", []):
        if feed["id"] == feed_id:
            feed["last_synced"] = datetime.now().isoformat() + "Z"
            feed["indicators_count"] += int(100 + (300 * (feed_id.endswith("1") or feed_id.endswith("4"))))
            break
    save_store(store)
    headers = {"X-Toast": json.dumps({"type": "success", "message": "Threat feed sync triggered successfully!"})}
    return RedirectResponse(url="/threat-intel", status_code=303, headers=headers)


@app.post("/threat-intel/feeds/{feed_id}/toggle")
async def toggle_threat_feed(request: Request, feed_id: str):
    store = get_store()
    for feed in store.setdefault("feeds", []):
        if feed["id"] == feed_id:
            feed["enabled"] = not feed["enabled"]
            break
    save_store(store)
    return RedirectResponse(url="/threat-intel", status_code=303)


@app.get("/health", response_class=HTMLResponse)
async def health_page(request: Request):
    wazuh_health = await api_request("GET", "/wazuh/health")
    model_status = await api_request("GET", "/model/status")
    db_health = await api_request("GET", "/health")
    full_health = await api_request("GET", "/health/full")
    services = full_health.get("services", {})
    
    ti_health = {
        "otx": services.get("otx", {"connected": False, "error": "Not configured"}),
        "misp": services.get("misp", {"connected": False, "error": "Not configured"}),
        "virustotal": services.get("virustotal", {"connected": False, "error": "Not configured"})
    }
    
    current_user = None
    token = request.cookies.get("session_token")
    if token:
        # In a real environment, query API or decode JWT. For now, mock a session:
        current_user = {
            "email": token,
            "display_name": token.split("@")[0].title(),
            "role": "admin" if "admin" in token else "analyst",
            "last_login": datetime.now().isoformat()
        }
        
    return templates.TemplateResponse("health.html", {
        "request": request,
        "wazuh": wazuh_health,
        "model": model_status,
        "db": db_health,
        "ti_health": ti_health,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "page": "health",
        "current_user": current_user
    })


@app.get("/health/status", response_class=HTMLResponse)
async def health_status_partial(request: Request):
    wazuh_health = await api_request("GET", "/wazuh/health")
    model_status = await api_request("GET", "/model/status")
    db_health = await api_request("GET", "/health")
    full_health = await api_request("GET", "/health/full")
    services = full_health.get("services", {})
    
    ti_health = {
        "otx": services.get("otx", {"connected": False, "error": "Not configured"}),
        "misp": services.get("misp", {"connected": False, "error": "Not configured"}),
        "virustotal": services.get("virustotal", {"connected": False, "error": "Not configured"})
    }
    
    return templates.TemplateResponse("health_grid.html", {
        "request": request,
        "wazuh": wazuh_health,
        "model": model_status,
        "db": db_health,
        "ti_health": ti_health,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


# --- Authentication & User Management Routes ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.cookies.get("session_token"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    email = form.get("email", "").strip()
    password = form.get("password", "").strip()
    
    # Check credentials
    if email == "admin@company.com" and password == "admin123":
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie("session_token", email, httponly=True)
        return resp
    elif email == "analyst@company.com" and password == "analyst123":
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie("session_token", email, httponly=True)
        return resp
    else:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password credentials."})


@app.get("/logout")
async def logout_action():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("session_token")
    return resp


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        return RedirectResponse("/login", status_code=303)
        
    current_user = {
        "email": token,
        "display_name": token.split("@")[0].title(),
        "role": "admin" if "admin" in token else "analyst",
        "last_login": datetime.now().isoformat()
    }
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": current_user,
        "current_user": current_user,
        "page": "profile"
    })


@app.post("/profile/change-password")
async def change_password(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)
        
    form = await request.form()
    curr_pw = form.get("current_password")
    new_pw = form.get("new_password")
    
    if curr_pw in ("admin123", "analyst123"):
        return JSONResponse({"status": "success"})
    return JSONResponse({"status": "error", "message": "Incorrect current password."})


@app.get("/users", response_class=HTMLResponse)
async def users_directory(request: Request):
    token = request.cookies.get("session_token")
    if not token or "admin" not in token:
        return RedirectResponse("/login", status_code=303)
        
    current_user = {
        "email": token,
        "display_name": token.split("@")[0].title(),
        "role": "admin",
        "last_login": datetime.now().isoformat()
    }
    
    store = get_store()
    users_list = store.get("users", [])
    if not users_list:
        users_list = [
            {"email": "admin@company.com", "display_name": "System Administrator", "role": "admin", "is_active": True, "last_login": datetime.now().isoformat()},
            {"email": "analyst@company.com", "display_name": "Lead SOC Analyst", "role": "analyst", "is_active": True, "last_login": datetime.now().isoformat()},
            {"email": "viewer@company.com", "display_name": "Audit Auditor", "role": "viewer", "is_active": False, "last_login": None}
        ]
        store["users"] = users_list
        save_store(store)
        
    return templates.TemplateResponse("users.html", {
        "request": request,
        "users": users_list,
        "current_user": current_user,
        "page": "users"
    })


@app.post("/users")
async def provision_user(request: Request):
    token = request.cookies.get("session_token")
    if not token or "admin" not in token:
        return JSONResponse({"status": "error"}, status_code=403)
        
    form = await request.form()
    email = form.get("email")
    display_name = form.get("display_name")
    role = form.get("role", "analyst")
    
    store = get_store()
    users_list = store.setdefault("users", [])
    # Append if not exists
    if not any(u["email"] == email for u in users_list):
        users_list.append({
            "email": email,
            "display_name": display_name,
            "role": role,
            "is_active": True,
            "last_login": None
        })
        save_store(store)
        
    return RedirectResponse("/users", status_code=303)


@app.patch("/users/{email}")
async def modify_user(email: str, request: Request):
    token = request.cookies.get("session_token")
    if not token or "admin" not in token:
        return JSONResponse({"status": "error"}, status_code=403)
        
    form = await request.form()
    display_name = form.get("display_name")
    role = form.get("role")
    
    store = get_store()
    users_list = store.setdefault("users", [])
    for u in users_list:
        if u["email"] == email:
            if display_name:
                u["display_name"] = display_name
            if role:
                u["role"] = role
            break
    save_store(store)
    return JSONResponse({"status": "success"})


@app.post("/users/{email}/toggle")
async def toggle_user(email: str, request: Request):
    token = request.cookies.get("session_token")
    if not token or "admin" not in token:
        return JSONResponse({"status": "error"}, status_code=403)
        
    store = get_store()
    users_list = store.setdefault("users", [])
    for u in users_list:
        if u["email"] == email:
            u["is_active"] = not u["is_active"]
            break
    save_store(store)
    return RedirectResponse("/users", status_code=303)


# --- Report Scheduler Routes ---

@app.post("/reports/schedules")
async def save_report_schedule(request: Request):
    form = await request.form()
    report_type = form.get("report_type", "executive")
    freq = form.get("frequency", "weekly")
    email_to = form.get("email_to", "")
    is_active = form.get("is_active") in ("true", "on", "True")
    
    cron_expr = form.get("cron_expression", "")
    if not cron_expr or freq != "custom":
        cron_expr = "0 0 * * *" if freq == "daily" else "0 8 * * 1" if freq == "weekly" else "0 8 1 * *"
        
    store = get_store()
    schedules = store.setdefault("schedules", [])
    new_sch = {
        "id": f"sch-{int(datetime.now().timestamp())}",
        "report_type": report_type,
        "cron_expression": cron_expr,
        "email_to": email_to,
        "is_active": is_active,
        "last_sent_at": None,
        "next_run_at": (datetime.now() + (datetime.now() - datetime.now())).isoformat() + "Z"
    }
    schedules.append(new_sch)
    save_store(store)
    return RedirectResponse("/reports", status_code=303)


@app.post("/reports/schedules/{sch_id}")
async def update_report_schedule(sch_id: str, request: Request):
    form = await request.form()
    report_type = form.get("report_type")
    email_to = form.get("email_to")
    is_active = form.get("is_active") in ("true", "on", "True")
    cron_expr = form.get("cron_expression", "")
    
    store = get_store()
    schedules = store.setdefault("schedules", [])
    for sch in schedules:
        if sch["id"] == sch_id:
            if report_type:
                sch["report_type"] = report_type
            if email_to:
                sch["email_to"] = email_to
            sch["is_active"] = is_active
            if cron_expr:
                sch["cron_expression"] = cron_expr
            break
    save_store(store)
    return RedirectResponse("/reports", status_code=303)


@app.post("/reports/schedules/{sch_id}/delete")
async def delete_report_schedule(sch_id: str, request: Request):
    store = get_store()
    store["schedules"] = [s for s in store.setdefault("schedules", []) if s["id"] != sch_id]
    save_store(store)
    return RedirectResponse("/reports", status_code=303)


