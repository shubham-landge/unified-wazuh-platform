"""Minimal HTTP wrapper around the maigret OSINT CLI.

Exposes two endpoints consumed by `shared.connectors.osint_maigret`:

- POST /lookup  {"username": "alice"} -> list of discovered profiles
- GET  /health  -> {"connected": true}

Maigret scans are CPU/network bound and run inside an asyncio thread pool so
uvicorn workers stay responsive. Results are not cached; callers (the OSINT
worker) are expected to persist them in PostgreSQL.
"""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Maigret OSINT API", version="1.0.0")

MAIGRET_TIMEOUT_SECONDS = 90
RESULTS_DIR = Path("/tmp/maigret_results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


class LookupRequest(BaseModel):
    username: str


def _maigret_installed() -> bool:
    return shutil.which("maigret") is not None


def _run_maigret(username: str) -> dict[str, Any]:
    """Run maigret synchronously and return parsed JSON output."""
    if not _maigret_installed():
        raise RuntimeError("maigret CLI is not installed")

    output_file = RESULTS_DIR / f"{username}.json"
    output_file.unlink(missing_ok=True)

    cmd = [
        "maigret",
        username,
        "--json",
        str(output_file),
        "--timeout",
        str(MAIGRET_TIMEOUT_SECONDS),
        "--no-recursion",
        "--no-color",
    ]
    logger.info("Running maigret for username=%s", username)
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAIGRET_TIMEOUT_SECONDS + 10,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("Maigret timed out for username=%s", username)
        raise RuntimeError("Maigret lookup timed out") from exc

    if not output_file.exists():
        return {}

    try:
        with output_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse maigret JSON: %s", exc)
        return {}

    # Maigret nests results under the username key.
    return data.get(username, data) if isinstance(data, dict) else data


def _normalize_maigret(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert maigret native JSON into the schema expected by the connector."""
    results: list[dict[str, Any]] = []
    sites = data.get("sites") if isinstance(data, dict) else None
    if not isinstance(sites, dict):
        return results

    for site_name, site_data in sites.items():
        if not isinstance(site_data, dict):
            continue
        status = site_data.get("status", {})
        if isinstance(status, dict):
            status_code = status.get("status")
        else:
            status_code = status
        if status_code != "claimed":
            continue

        url_user = site_data.get("url_user") or site_data.get("url")
        if not url_user:
            continue

        results.append(
            {
                "source": site_name.lower(),
                "profile_url": url_user,
                "name": site_data.get("username") or site_data.get("name"),
                "location": site_data.get("location") or site_data.get("country"),
                "raw_data": site_data,
            }
        )

    return results


@app.get("/health")
async def health():
    return {
        "connected": _maigret_installed(),
        "service": "maigret",
    }


@app.post("/lookup")
async def lookup(req: LookupRequest):
    if not req.username or not req.username.strip():
        raise HTTPException(400, "username is required")

    import asyncio

    try:
        raw = await asyncio.to_thread(_run_maigret, req.username.strip())
    except RuntimeError as exc:
        logger.error("Maigret lookup failed: %s", exc)
        raise HTTPException(503, str(exc)) from exc

    results = _normalize_maigret(raw)
    logger.info("Maigret found %d profiles for username=%s", len(results), req.username)
    return results
