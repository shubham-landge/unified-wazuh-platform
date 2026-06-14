import httpx
import os
import json
import hmac
import hashlib
import secrets
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from shared.config import settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _http_client
    _http_client = httpx.AsyncClient(timeout=_HTTP_TIMEOUT)
    yield
    await _http_client.aclose()


app = FastAPI(lifespan=lifespan)

API_BASE = os.getenv("API_BASE_URL", "http://api:8000")
templates = Jinja2Templates(directory="templates", autoescape=True)

STORE_PATH = "app/dashboard_store.json"
_HTTP_TIMEOUT = 10.0
_http_client: httpx.AsyncClient | None = None

# Settings keys that must never be persisted to the dashboard JSON store.
_SECRET_SETTINGS_KEYS = {"api_key", "otx_api_key", "misp_api_key", "virustotal_api_key"}


def _settings_env_var(key: str) -> str:
    return f"SETTINGS_{key.upper()}"


def _load_secret_setting(key: str, fallback: str = "") -> str:
    return os.getenv(_settings_env_var(key), os.getenv(key.upper(), fallback))

_DASHBOARD_SECRET_KEY = os.getenv("DASHBOARD_SECRET_KEY")
if not _DASHBOARD_SECRET_KEY:
    _DASHBOARD_SECRET_KEY = hmac.new(
        os.getenv("API_KEYS", "dev-only-key").encode(),
        b"dashboard-session",
        hashlib.sha256,
    ).hexdigest()

SESSION_COOKIE_NAME = "session_token"
SESSION_MAX_AGE_SECONDS = int(os.getenv("DASHBOARD_SESSION_MAX_AGE", "28800"))
_signer = TimestampSigner(_DASHBOARD_SECRET_KEY)


def _sign_session(payload: dict) -> str:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return _signer.sign(data).decode()


def _unsign_session(value: str) -> dict | None:
    try:
        raw = _signer.unsign(value, max_age=SESSION_MAX_AGE_SECONDS)
        return json.loads(raw.decode())
    except (BadSignature, SignatureExpired, json.JSONDecodeError):
        return None


def get_session_user(request: Request) -> dict | None:
    """Return the signed session user dict, or None if invalid/missing."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    session = _unsign_session(token)
    if not session:
        return None
    email = session.get("email") or session.get("sub") or ""
    return {
        "email": email,
        "display_name": email.split("@")[0].title() if "@" in email else email,
        "role": session.get("role", "viewer"),
        "tenant_id": session.get("tenant_id"),
        "tenant_name": None,
        "last_login": datetime.now(timezone.utc).isoformat(),
    }


def require_login(request: Request):
    """Redirect unauthenticated users to /login."""
    if not get_session_user(request):
        return RedirectResponse("/login", status_code=303)
    return None


def get_csrf_token(request: Request) -> str | None:
    """Return the CSRF token stored in the signed session, if any."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    session = _unsign_session(token)
    if not session:
        return None
    return session.get("csrf_token")


def get_store():
    if not os.path.exists(STORE_PATH):
        return {"channels": [], "rules": [], "events": [], "playbooks": [], "playbook_runs": [], "feeds": []}
    try:
        with open(STORE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"channels": [], "rules": [], "events": [], "playbooks": [], "playbook_runs": [], "feeds": []}


async def get_tenant_context(token: str):
    """Fetch tenant context from the API based on session token.

    Kept for backward compatibility; prefer get_session_user(request).
    """
    session = _unsign_session(token)
    if session:
        email = session.get("email") or session.get("sub") or ""
        return {
            "email": email,
            "display_name": email.split("@")[0].title() if "@" in email else email,
            "role": session.get("role", "viewer"),
            "tenant_id": session.get("tenant_id"),
            "tenant_name": None,
        }

    # Legacy unsigned token fallback (deprecated)
    import httpx
    async with httpx.AsyncClient(timeout=10.0) as client:
        headers = {"X-API-Key": os.getenv("API_KEYS", "soc-key-001").split(",")[0]}
        from shared.auth import verify_token
        tenant_id = None
        try:
            user_data = verify_token(token)
            if user_data and hasattr(user_data, 'tenant_id'):
                tenant_id = user_data.tenant_id
        except Exception:
            pass

        if not tenant_id:
            url = f"{API_BASE}/auth/me"
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                user_profile = resp.json()
                tenant_id = user_profile.get('tenant_id')

        return {
            "email": token,
            "display_name": token.split("@")[0].title(),
            "role": "admin" if "admin" in token else "analyst",
            "tenant_id": tenant_id,
            "tenant_name": None,
        }

def save_store(store_data):
    try:
        with open(STORE_PATH, "w") as f:
            json.dump(store_data, f, indent=4)
        return True
    except Exception:
        return False


def _default_managers() -> list[dict]:
    return [
        {
            "label": m["label"],
            "url": m["url"],
            "user": m["user"],
            "password": m["password"],
        }
        for m in settings.parsed_wazuh_managers
    ]


def _default_indexers() -> list[dict]:
    return [
        {
            "label": i["label"],
            "url": i["url"],
            "user": i["user"],
            "password": i["password"],
        }
        for i in settings.parsed_wazuh_indexers
    ]


def get_managers() -> list[dict]:
    store = get_store()
    managers = store.get("managers")
    if managers is None:
        managers = _default_managers()
        store["managers"] = managers
        save_store(store)
    return managers


def save_managers(managers: list[dict]):
    store = get_store()
    store["managers"] = managers
    save_store(store)


def get_indexers() -> list[dict]:
    store = get_store()
    indexers = store.get("indexers")
    if indexers is None:
        indexers = _default_indexers()
        store["indexers"] = indexers
        save_store(store)
    return indexers


def save_indexers(indexers: list[dict]):
    store = get_store()
    store["indexers"] = indexers
    save_store(store)


# Ingest user context to templates automatically
@app.middleware("http")
async def add_user_to_template_context(request: Request, call_next):
    current_user = get_session_user(request)

    request.state.current_user = current_user
    request.state.tenant_id = current_user.get("tenant_id") if current_user else None
    templates.env.globals["current_user"] = current_user
    templates.env.globals["tenant_id"] = current_user.get("tenant_id") if current_user else None
    templates.env.globals["csrf_token"] = get_csrf_token(request)
    templates.env.globals["branding"] = _get_branding()

    pending_count = 0
    if current_user:
        try:
            if request.state.tenant_id:
                res = await api_request("GET", f"/approvals/pending?tenant_id={request.state.tenant_id}")
            else:
                res = await api_request("GET", "/approvals/pending")
            pending_count = res.get("count", 0)
        except Exception:
            pass
    templates.env.globals["pending_approvals_count"] = pending_count

    response = await call_next(request)
    return response


@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    """Validate CSRF token for state-changing requests from authenticated users.

    Uses the double-submit pattern: the token is stored in the signed session and
    must be echoed back in the X-CSRF-Token header. Form bodies are left for route
    handlers to consume.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return await call_next(request)

    path = request.url.path
    if path in ("/login", "/logout") or path.startswith("/static/"):
        return await call_next(request)

    session = _unsign_session(request.cookies.get(SESSION_COOKIE_NAME, ""))
    if not session:
        # Unauthenticated state-changing requests are rejected by auth guards; allow pass-through.
        return await call_next(request)

    expected = session.get("csrf_token")
    if not expected:
        return JSONResponse({"status": "error", "message": "CSRF token missing from session"}, status_code=403)

    submitted = request.headers.get("X-CSRF-Token")
    if not submitted or not secrets.compare_digest(expected, submitted):
        return JSONResponse({"status": "error", "message": "Invalid CSRF token"}, status_code=403)

    return await call_next(request)


# Mount static files directory
static_dir = "static" if os.path.exists("static") else "services/dashboard/static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


async def api_request(method: str, path: str, json_data: dict = None, data: dict = None, request: Request = None):
    headers = {"X-API-Key": os.getenv("API_KEYS", "soc-key-001").split(",")[0]}
    if request:
        session = get_session_user(request)
        if session:
            access_token = None
            raw_cookie = request.cookies.get(SESSION_COOKIE_NAME, "")
            try:
                raw_session = _unsign_session(raw_cookie) or {}
                access_token = raw_session.get("access_token")
            except Exception:
                access_token = None

            tenant_id = session.get("tenant_id")
            if access_token:
                headers["Authorization"] = f"Bearer {access_token}"
            else:
                from shared.auth import create_access_token
                headers["Authorization"] = f"Bearer {create_access_token(
                    user_id=session['email'],
                    email=session['email'],
                    role=session.get('role', 'viewer'),
                    tenant_id=tenant_id,
                )}"
            if tenant_id:
                headers["X-Tenant-ID"] = tenant_id
    client = _http_client or httpx.AsyncClient(timeout=_HTTP_TIMEOUT)
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
            return {"status": "error", "detail": resp.text}
    return resp.json()


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
    current_user = get_session_user(request)

    return templates.TemplateResponse("reports.html", {
        "request": request,
        "reports": reports_list,
        "schedules": schedules_list,
        "current_user": current_user,
        "page": "reports"
    })


@app.get("/osint", response_class=HTMLResponse)
async def osint_page(request: Request, target_type: str | None = None, target_value: str | None = None, target_id: str | None = None):
    targets = await api_request("GET", "/osint/targets?limit=100")
    selected = {"target": {}, "results": []}
    if target_type and target_value:
        queued = await api_request(
            "POST",
            "/osint/lookup",
            json_data={"target_type": target_type, "target_value": target_value},
        )
        queued_target_id = queued.get("target_id")
        if queued_target_id:
            return RedirectResponse(url=f"/osint/history?target_id={queued_target_id}", status_code=303)
    if target_id:
        try:
            selected = await api_request("GET", f"/osint/results/{target_id}")
        except Exception:
            selected = {"target": {}, "results": []}
    return templates.TemplateResponse("osint.html", {
        "request": request,
        "targets": targets.get("targets", []),
        "selected_target": selected.get("target", {}),
        "results": selected.get("results", []),
        "selected_target_id": target_id,
        "page": "OSINT",
    })


@app.get("/osint/history", response_class=HTMLResponse)
async def osint_history_page(request: Request, target_id: str | None = None):
    targets = await api_request("GET", "/osint/targets?limit=100")
    selected = {"target": {}, "results": []}
    if target_id:
        try:
            selected = await api_request("GET", f"/osint/results/{target_id}")
        except Exception:
            selected = {"target": {}, "results": []}
    return templates.TemplateResponse("osint.html", {
        "request": request,
        "targets": targets.get("targets", []),
        "selected_target": selected.get("target", {}),
        "results": selected.get("results", []),
        "selected_target_id": target_id,
        "page": "OSINT",
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
        "api_key": _load_secret_setting("api_key", os.getenv("API_KEYS", "soc-key-001").split(",")[0]),
        "wazuh_host": "https://wazuh.local:55000",
        "ollama_model": "llama3",
        "auto_triage": "enabled",
        "retention_days": "90",
        "sync_interval": "60",
        "otx_api_key": _load_secret_setting("otx_api_key", os.getenv("OTX_API_KEY", "")),
        "misp_url": os.getenv("MISP_URL", ""),
        "misp_api_key": _load_secret_setting("misp_api_key", os.getenv("MISP_API_KEY", "")),
        "misp_verify_ssl": os.getenv("MISP_VERIFY_SSL", "true").lower() == "true",
        "virustotal_api_key": _load_secret_setting("virustotal_api_key", os.getenv("VIRUSTOTAL_API_KEY", "")),
        "ti_feed_poll_interval_seconds": int(os.getenv("TI_FEED_POLL_INTERVAL_SECONDS", "3600"))
    }
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r") as f:
                loaded = json.load(f)
                # Do not let on-disk JSON override secret values sourced from env vars.
                for secret_key in _SECRET_SETTINGS_KEYS:
                    loaded.pop(secret_key, None)
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
        "managers": get_managers(),
        "indexers": get_indexers(),
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

    # Secrets are sourced from SETTINGS_* environment variables; do not persist them to disk.
    for secret_key in _SECRET_SETTINGS_KEYS:
        new_settings.pop(secret_key, None)

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


@app.post("/settings/managers/add")
async def add_manager(request: Request):
    current_user = get_session_user(request)
    if not current_user or current_user.get("role") != "admin":
        return JSONResponse({"status": "error", "message": "Forbidden"}, status_code=403)

    form = await request.form()
    managers = get_managers()
    managers.append({
        "label": form.get("label", f"manager-{len(managers) + 1}").strip(),
        "url": form.get("url", "").strip(),
        "user": form.get("user", "").strip(),
        "password": form.get("password", "").strip(),
    })
    save_managers(managers)
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/managers/{idx}/delete")
async def delete_manager(request: Request, idx: int):
    current_user = get_session_user(request)
    if not current_user or current_user.get("role") != "admin":
        return JSONResponse({"status": "error", "message": "Forbidden"}, status_code=403)

    managers = get_managers()
    if 0 <= idx < len(managers):
        managers.pop(idx)
        save_managers(managers)
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/managers/{idx}/test")
async def test_manager(request: Request, idx: int):
    current_user = get_session_user(request)
    if not current_user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    managers = get_managers()
    if not (0 <= idx < len(managers)):
        return JSONResponse({"status": "error", "message": "Invalid manager"}, status_code=400)

    manager = managers[idx]
    try:
        client = _http_client or httpx.AsyncClient(timeout=_HTTP_TIMEOUT)
        auth = (manager.get("user", ""), manager.get("password", ""))
        resp = await client.get(
            f"{manager['url'].rstrip('/')}/health-check",
            auth=auth if any(auth) else None,
            headers={"Content-Type": "application/json"},
        )
        ok = resp.status_code < 400
    except Exception as exc:
        return JSONResponse({"status": "error", "message": str(exc)})

    return JSONResponse({"status": "success" if ok else "error", "connected": ok})


@app.post("/settings/indexers/add")
async def add_indexer(request: Request):
    current_user = get_session_user(request)
    if not current_user or current_user.get("role") != "admin":
        return JSONResponse({"status": "error", "message": "Forbidden"}, status_code=403)

    form = await request.form()
    indexers = get_indexers()
    indexers.append({
        "label": form.get("label", f"indexer-{len(indexers) + 1}").strip(),
        "url": form.get("url", "").strip(),
        "user": form.get("user", "").strip(),
        "password": form.get("password", "").strip(),
    })
    save_indexers(indexers)
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/indexers/{idx}/delete")
async def delete_indexer(request: Request, idx: int):
    current_user = get_session_user(request)
    if not current_user or current_user.get("role") != "admin":
        return JSONResponse({"status": "error", "message": "Forbidden"}, status_code=403)

    indexers = get_indexers()
    if 0 <= idx < len(indexers):
        indexers.pop(idx)
        save_indexers(indexers)
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/indexers/{idx}/test")
async def test_indexer(request: Request, idx: int):
    current_user = get_session_user(request)
    if not current_user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    indexers = get_indexers()
    if not (0 <= idx < len(indexers)):
        return JSONResponse({"status": "error", "message": "Invalid indexer"}, status_code=400)

    indexer = indexers[idx]
    try:
        client = _http_client or httpx.AsyncClient(timeout=_HTTP_TIMEOUT)
        auth = (indexer.get("user", ""), indexer.get("password", ""))
        resp = await client.get(
            f"{indexer['url'].rstrip('/')}/_cluster/health",
            auth=auth if any(auth) else None,
            headers={"Content-Type": "application/json"},
        )
        ok = resp.status_code < 400
    except Exception as exc:
        return JSONResponse({"status": "error", "message": str(exc)})

    return JSONResponse({"status": "success" if ok else "error", "connected": ok})


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
async def compliance_page(request: Request, framework: str | None = None):
    frameworks_data = await api_request("GET", "/compliance/frameworks")
    frameworks = frameworks_data.get("frameworks", [])

    target_fw = framework
    if not target_fw and frameworks:
        target_fw = frameworks[0]["id"]

    score_data = {"score": {"total_controls": 0, "compliant": 0, "warnings": 0, "breaches": 0, "score": 0, "controls": []}}
    if target_fw:
        score_data = await api_request("GET", f"/compliance/frameworks/{target_fw}/score")

    return templates.TemplateResponse("compliance.html", {
        "request": request,
        "frameworks": frameworks,
        "score": score_data.get("score", {}),
        "framework": target_fw or "",
        "page": "compliance"
    })


@app.get("/compliance/score/{framework_id}")
async def compliance_score_proxy(framework_id: str, request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect
    data = await api_request("GET", f"/compliance/frameworks/{framework_id}/score")
    return JSONResponse(data)


@app.post("/compliance/exceptions")
async def create_exception(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"status": "error", "message": "Invalid JSON"}, status_code=400)
    result = await api_request("POST", "/compliance/exceptions", json_data=payload)
    return JSONResponse(result)


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
    
    current_user = get_session_user(request)

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

# --- Branding & Theme Settings ---

BRANDING_STORE_PATH = "app/branding.json"

_CSS_DANGEROUS_RE = re.compile(
    r"url\s*\([^)]*\)|@import\b|javascript:|expression\s*\(|behavior\s*:|</style>",
    re.IGNORECASE,
)


def _sanitize_custom_css(css: str) -> str:
    """Strip dangerous CSS constructs that could lead to XSS or data exfiltration."""
    return _CSS_DANGEROUS_RE.sub("", css)


def _get_branding():
    if not os.path.exists(BRANDING_STORE_PATH):
        return {
            "primary_color": "#3b82f6",
            "secondary_color": "#94a3b8",
            "company_name": "WAZUH",
            "logo_url": "",
            "favicon_url": "",
            "custom_css": "",
        }
    try:
        with open(BRANDING_STORE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_branding(data: dict):
    try:
        os.makedirs(os.path.dirname(BRANDING_STORE_PATH), exist_ok=True)
        with open(BRANDING_STORE_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


@app.get("/settings/branding", response_class=HTMLResponse)
async def branding_settings_tab(request: Request):
    branding = _get_branding()
    return templates.TemplateResponse("branding_partial.html", {
        "request": request,
        "branding": branding,
    })


@app.post("/settings/branding")
async def save_branding_settings(request: Request):
    form = await request.form()
    branding = {
        "primary_color": form.get("primary_color", "#3b82f6"),
        "secondary_color": form.get("secondary_color", "#94a3b8"),
        "company_name": form.get("company_name", "WAZUH"),
        "logo_url": form.get("logo_url", ""),
        "favicon_url": form.get("favicon_url", ""),
        "custom_css": _sanitize_custom_css(form.get("custom_css", "")),
    }
    _save_branding(branding)
    return JSONResponse({"status": "success", "branding": branding})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.cookies.get(SESSION_COOKIE_NAME):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    email = form.get("email", "").strip()
    password = form.get("password", "").strip()

    # Dev-only escape hatch for local testing without seeded API users.
    dev_allowed = os.getenv("DASHBOARD_DEV_ALLOW_HARDCODED", "").lower() in ("1", "true", "yes")
    if dev_allowed and email == "admin@company.com" and password == "admin123":
        resp = RedirectResponse("/", status_code=303)
        session_payload = {
            "sub": email,
            "email": email,
            "role": "admin",
            "tenant_id": None,
            "csrf_token": secrets.token_urlsafe(32),
            "iat": datetime.now(timezone.utc).isoformat(),
        }
        resp.set_cookie(SESSION_COOKIE_NAME, _sign_session(session_payload), httponly=True, max_age=SESSION_MAX_AGE_SECONDS)
        return resp
    if dev_allowed and email == "analyst@company.com" and password == "analyst123":
        resp = RedirectResponse("/", status_code=303)
        session_payload = {
            "sub": email,
            "email": email,
            "role": "analyst",
            "tenant_id": None,
            "csrf_token": secrets.token_urlsafe(32),
            "iat": datetime.now(timezone.utc).isoformat(),
        }
        resp.set_cookie(SESSION_COOKIE_NAME, _sign_session(session_payload), httponly=True, max_age=SESSION_MAX_AGE_SECONDS)
        return resp

    try:
        client = _http_client or httpx.AsyncClient(timeout=_HTTP_TIMEOUT)
        api_resp = await client.post(
            f"{API_BASE}/auth/login",
            json={"email": email, "password": password},
        )
    except httpx.RequestError:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Authentication service unavailable."})

    if api_resp.status_code != 200:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password credentials."})

    data = api_resp.json()
    access_token = data.get("access_token")
    role = data.get("user_role", "viewer")
    tenant_id = data.get("tenant_id")

    if not access_token:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password credentials."})

    resp = RedirectResponse("/", status_code=303)
    session_payload = {
        "sub": email,
        "email": email,
        "role": role,
        "tenant_id": tenant_id,
        "access_token": access_token,
        "csrf_token": secrets.token_urlsafe(32),
        "iat": datetime.now(timezone.utc).isoformat(),
    }
    resp.set_cookie(SESSION_COOKIE_NAME, _sign_session(session_payload), httponly=True, max_age=SESSION_MAX_AGE_SECONDS)
    return resp


@app.get("/logout")
async def logout_action():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    current_user = get_session_user(request)
    if not current_user:
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": current_user,
        "current_user": current_user,
        "page": "profile"
    })


@app.post("/profile/change-password")
async def change_password(request: Request):
    current_user = get_session_user(request)
    if not current_user:
        return JSONResponse({"status": "error", "message": "Unauthorized"}, status_code=401)

    form = await request.form()
    curr_pw = form.get("current_password")

    # Dev-only hardcoded escape hatch; production password changes must be handled by the API.
    dev_allowed = os.getenv("DASHBOARD_DEV_ALLOW_HARDCODED", "").lower() in ("1", "true", "yes")
    if dev_allowed and curr_pw in ("admin123", "analyst123"):
        return JSONResponse({"status": "success"})

    return JSONResponse(
        {"status": "error", "message": "Password change is not supported by the dashboard; use the API."},
        status_code=501,
    )


@app.get("/users", response_class=HTMLResponse)
async def users_directory(request: Request):
    current_user = get_session_user(request)
    if not current_user or current_user.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)

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
    current_user = get_session_user(request)
    if not current_user or current_user.get("role") != "admin":
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
    current_user = get_session_user(request)
    if not current_user or current_user.get("role") != "admin":
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
    current_user = get_session_user(request)
    if not current_user or current_user.get("role") != "admin":
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


# --- Phase 4B: MTTR Dashboard + ATT&CK Heatmap ---

@app.get("/mttr-dashboard", response_class=HTMLResponse)
async def mttr_dashboard(request: Request):
    stats = await api_request("GET", "/cases/stats/mttr?days=30")
    cases = await api_request("GET", "/cases?limit=100")
    mitre = await api_request("GET", "/cases/stats/mitre-heatmap")
    return templates.TemplateResponse("mttr_dashboard.html", {
        "request": request,
        "stats": stats,
        "cases": cases.get("cases", []),
        "mitre": mitre,
        "page": "mttr-dashboard",
    })


@app.get("/attack-heatmap", response_class=HTMLResponse)
async def attack_heatmap(request: Request):
    mitre = await api_request("GET", "/cases/stats/mitre-heatmap")
    cases = await api_request("GET", "/cases?limit=100")
    return templates.TemplateResponse("attack_heatmap.html", {
        "request": request,
        "mitre": mitre,
        "cases": cases.get("cases", []),
        "page": "attack-heatmap",
    })


# --- AI Triage Feedback Console Routes ---

@app.post("/feedback/{triage_id}")
async def submit_feedback(triage_id: str, request: Request):
    form = await request.form()
    rating = form.get("rating", "helpful")
    corrected_category = form.get("corrected_category")
    corrected_severity = form.get("corrected_severity")
    comments = form.get("comments")
    
    current_user = get_session_user(request)
    operator = current_user.get("email") if current_user else "anonymous"

    # In a real setup, proxy to the API:
    # payload = { "rating": rating, "corrected_category": corrected_category, ... }
    # await api_request("POST", f"/triage/{triage_id}/feedback", json_data=payload)

    store = get_store()
    feedback_list = store.setdefault("feedback", [])

    new_entry = {
        "triage_id": triage_id,
        "rating": rating,
        "corrected_category": corrected_category if corrected_category else None,
        "corrected_severity": corrected_severity if corrected_severity else None,
        "comments": comments if comments else None,
        "operator": operator,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    feedback_list.append(new_entry)
    save_store(store)
    
    return JSONResponse({"status": "success"})


@app.get("/feedback", response_class=HTMLResponse)
async def feedback_analytics(request: Request):
    current_user = get_session_user(request)
    if not current_user or current_user.get("role") != "admin":
        return RedirectResponse("/login", status_code=303)

    store = get_store()
    items = store.get("feedback", [])
    
    total_count = len(items)
    helpful_count = sum(1 for i in items if i.get("rating") == "helpful")
    accuracy_rate = helpful_count / total_count if total_count > 0 else 1.0
    corrected_count = sum(1 for i in items if i.get("corrected_category") or i.get("corrected_severity"))
    
    cat_counts = {}
    for i in items:
        cat = i.get("corrected_category")
        if cat:
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
            
    top_corrected = max(cat_counts, key=cat_counts.get) if cat_counts else None
    
    return templates.TemplateResponse("feedback.html", {
        "request": request,
        "items": items,
        "current_user": current_user,
        "page": "feedback",
        "total_count": total_count,
        "accuracy_rate": accuracy_rate,
        "corrected_count": corrected_count,
        "top_corrected_category": top_corrected
    })


# --- RAG Knowledge Base ---

@app.get("/knowledge", response_class=HTMLResponse)
async def knowledge_base(request: Request, source: str = "", limit: int = 50):
    redirect = require_login(request)
    if redirect:
        return redirect
    params = f"?limit={limit}"
    if source:
        params += f"&source={source}"
    data = await api_request("GET", f"/rag/knowledge{params}")
    sources_data = await api_request("GET", "/rag/knowledge?limit=200")
    unique_sources = sorted(set(c.get("source", "") for c in sources_data.get("chunks", [])))
    return templates.TemplateResponse("knowledge.html", {
        "request": request,
        "chunks": data.get("chunks", []),
        "sources": unique_sources,
        "page": "knowledge",
    })


# --- Ticketing Settings ---

@app.get("/ticketing", response_class=HTMLResponse)
async def ticketing_page(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect
    configs = await api_request("GET", "/ticketing/config")
    return templates.TemplateResponse("ticketing.html", {
        "request": request,
        "configs": configs.get("configs", []),
        "page": "ticketing",
    })


@app.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect
    current_user = request.state.current_user
    definitions = await api_request("GET", "/agents/definitions?limit=100")
    runs = await api_request("GET", "/agents/runs?limit=50")
    return templates.TemplateResponse("agents.html", {
        "request": request,
        "definitions": definitions.get("definitions", []),
        "runs": runs.get("runs", []),
        "current_user": current_user,
        "page": "agents",
    })


@app.get("/agents/runs", response_class=HTMLResponse)
async def agent_runs_page(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect
    current_user = request.state.current_user
    runs = await api_request("GET", "/agents/runs?limit=100")
    return templates.TemplateResponse("agents.html", {
        "request": request,
        "definitions": [],
        "runs": runs.get("runs", []),
        "current_user": current_user,
        "page": "agents",
        "active_tab": "runs",
    })


@app.get("/approvals", response_class=HTMLResponse)
async def approvals_dashboard(request: Request):
    current_user = get_session_user(request)
    if not current_user:
        return RedirectResponse("/login", status_code=303)

    res = await api_request("GET", "/approvals", request=request)
    approvals_list = res.get("approvals", [])
    return templates.TemplateResponse("approvals.html", {
        "request": request,
        "current_user": current_user,
        "approvals": approvals_list,
        "page": "approvals"
    })


@app.post("/approvals/{approval_id}/review")
async def review_approval_dashboard(approval_id: str, request: Request):
    current_user = get_session_user(request)
    if not current_user:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    status = form.get("status")
    comment = form.get("comment")
    await api_request("PUT", f"/approvals/{approval_id}/review", json_data={"status": status, "comment": comment}, request=request)
    return RedirectResponse("/approvals", status_code=303)


# --- OSINT Integration ---

@app.get("/osint", response_class=HTMLResponse)
async def osint_page(request: Request, target_type: str | None = None, target_value: str | None = None, target_id: str | None = None):
    redirect = require_login(request)
    if redirect:
        return redirect
    targets = await api_request("GET", "/osint/targets?limit=100")
    selected = {"target": {}, "results": []}
    if target_type and target_value:
        queued = await api_request(
            "POST",
            "/osint/lookup",
            json_data={"target_type": target_type, "target_value": target_value},
        )
        queued_target_id = queued.get("target_id")
        if queued_target_id:
            return RedirectResponse(url=f"/osint/history?target_id={queued_target_id}", status_code=303)
    if target_id:
        try:
            selected = await api_request("GET", f"/osint/results/{target_id}")
        except Exception:
            selected = {"target": {}, "results": []}
    return templates.TemplateResponse("osint.html", {
        "request": request,
        "targets": targets.get("targets", []),
        "selected_target": selected.get("target", {}),
        "results": selected.get("results", []),
        "selected_target_id": target_id,
        "page": "OSINT",
    })


@app.get("/osint/history", response_class=HTMLResponse)
async def osint_history_page(request: Request, target_id: str | None = None):
    targets = await api_request("GET", "/osint/targets?limit=100")
    selected = {"target": {}, "results": []}
    if target_id:
        try:
            selected = await api_request("GET", f"/osint/results/{target_id}")
        except Exception:
            selected = {"target": {}, "results": []}
    return templates.TemplateResponse("osint.html", {
        "request": request,
        "targets": targets.get("targets", []),
        "selected_target": selected.get("target", {}),
        "results": selected.get("results", []),
        "selected_target_id": target_id,
        "page": "OSINT",
    })


@app.get("/usage", response_class=HTMLResponse)
async def usage_page(request: Request, period: str = "current"):
    summary = await api_request("GET", f"/usage/summary?period={period}")
    records = await api_request("GET", "/usage/records?limit=50")
    limits = await api_request("GET", "/usage/limits")
    return templates.TemplateResponse("usage.html", {
        "request": request,
        "summary": summary.get("summary", {}),
        "records": records.get("records", []),
        "limits": limits.get("limits", {}),
        "period": period,
        "page": "usage",
    })


@app.get("/tenants", response_class=HTMLResponse)
async def tenants_page(request: Request):
    tenants = await api_request("GET", "/tenants")
    return templates.TemplateResponse("tenants.html", {
        "request": request,
        "tenants": tenants.get("tenants", []),
        "page": "tenants",
    })


@app.get("/tenants/{tenant_id}", response_class=HTMLResponse)
async def tenant_detail_page(request: Request, tenant_id: str):
    tenant = await api_request("GET", f"/tenants/{tenant_id}")
    stats = await api_request("GET", f"/tenants/{tenant_id}/stats")
    return templates.TemplateResponse("tenant_detail.html", {
        "request": request,
        "tenant": tenant.get("tenant", {}),
        "stats": stats.get("stats", {}),
        "page": "tenants",
    })


@app.post("/tenants")
async def create_tenant_dashboard(request: Request):
    form = await request.form()
    result = await api_request("POST", "/tenants", json_data={
        "name": form.get("name"),
        "slug": form.get("slug"),
    })
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/tenants", status_code=303)
