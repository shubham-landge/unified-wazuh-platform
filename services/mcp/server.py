"""MCP-compatible HTTP server exposing SOC platform tools.

This is a minimal HTTP server that follows the Model Context Protocol
convention for tool discovery and invocation. Each tool wraps an existing
router or service endpoint.

Replace with `fastmcp.FastMCP` once the `mcp` SDK package is available
in the deployment environment.
"""

import json
import logging
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared.config import settings

logger = logging.getLogger(__name__)

app = FastAPI(title="SOC MCP Server", version="1.0.0")

API_BASE = settings.api_base_url if hasattr(settings, "api_base_url") else "http://api:8000"


class ToolRequest(BaseModel):
    tool: str
    params: dict[str, Any] = {}


TOOL_DEFINITIONS = [
    {
        "name": "list_alerts",
        "description": "List recent alerts with optional severity filter",
        "parameters": {"limit": {"type": "integer", "default": 10}, "severity": {"type": "string", "default": None}},
    },
    {
        "name": "get_triage",
        "description": "Get AI triage result for a specific alert",
        "parameters": {"alert_id": {"type": "string"}},
    },
    {
        "name": "get_agents",
        "description": "List Wazuh agents",
        "parameters": {"limit": {"type": "integer", "default": 100}},
    },
    {
        "name": "list_rules",
        "description": "List Wazuh rules",
        "parameters": {"limit": {"type": "integer", "default": 50}},
    },
    {
        "name": "get_stats",
        "description": "Get SOC platform statistics",
        "parameters": {},
    },
    {
        "name": "list_vulnerabilities",
        "description": "List detected vulnerabilities",
        "parameters": {"limit": {"type": "integer", "default": 50}},
    },
    {
        "name": "create_case",
        "description": "Create a new investigation case (write operation)",
        "parameters": {"title": {"type": "string"}, "description": {"type": "string", "default": ""}, "severity": {"type": "string", "default": "medium"}},
    },
    {
        "name": "run_playbook",
        "description": "Trigger a SOAR playbook (write operation, gated)",
        "parameters": {"playbook_id": {"type": "string"}, "alert_id": {"type": "string", "default": None}},
    },
]


@app.get("/tools")
async def list_tools():
    return {"tools": TOOL_DEFINITIONS}


def _first_api_key() -> str:
    keys = settings.api_keys
    if isinstance(keys, list):
        return keys[0] if keys else ""
    if isinstance(keys, str):
        return keys.split(",")[0].strip() if keys else ""
    return ""


@app.post("/tools/call")
async def call_tool(req: ToolRequest):
    headers = {"X-API-Key": _first_api_key()}

    try:
        async with httpx.AsyncClient(base_url=API_BASE, timeout=30.0) as client:
            if req.tool == "list_alerts":
                resp = await client.get("/alerts/recent", params=req.params, headers=headers)
            elif req.tool == "get_triage":
                alert_id = req.params.get("alert_id")
                if not alert_id:
                    raise HTTPException(400, "alert_id required")
                resp = await client.get(f"/triage/{alert_id}", headers=headers)
            elif req.tool == "get_agents":
                resp = await client.get("/agents/definitions", headers=headers, params=req.params)
            elif req.tool == "list_rules":
                resp = await client.get("/rules", headers=headers, params=req.params)
            elif req.tool == "get_stats":
                resp = await client.get("/health/full", headers=headers)
            elif req.tool == "list_vulnerabilities":
                resp = await client.get("/vulnerabilities", headers=headers, params=req.params)
            elif req.tool == "create_case":
                resp = await client.post("/cases", json=req.params, headers=headers)
            elif req.tool == "run_playbook":
                resp = await client.post("/soar/executions", json=req.params, headers=headers)
            else:
                raise HTTPException(400, f"Unknown tool: {req.tool}")
    except httpx.RequestError as exc:
        logger.error("MCP tool %s failed to reach API at %s: %s", req.tool, API_BASE, exc)
        raise HTTPException(502, f"Unable to reach SOC API at {API_BASE}: {exc}") from exc

    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text[:500])

    return resp.json()
