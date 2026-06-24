import asyncio
import json
import os
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select

ROOT = Path(__file__).resolve().parents[2]
API_DIR = ROOT / "services" / "api"
for path in (ROOT, API_DIR):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

try:
    from mcp.server.fastmcp import FastMCP
except Exception:
    class FastMCP:
        def __init__(self, name: str):
            self.name = name
            self.tools: dict[str, Any] = {}

        def tool(self, name: str | None = None):
            def decorator(func):
                self.tools[name or func.__name__] = func
                return func

            return decorator

        def run(self, *args, **kwargs):
            raise RuntimeError("mcp package is not installed")

from app.db import async_session
from app.routers.cases import CaseCreate, create_case as api_create_case
from shared.config import settings
from shared.connectors.circuit_breaker import CircuitBreaker, CircuitBreakerOpenError
from shared.models.alert import Alert
from shared.models.ai_triage_result import AiTriageResult
from shared.models.asset import Asset
from shared.models.case import Case
from shared.models.playbook import Playbook
from shared.models.vulnerability import Vulnerability
from shared.soar.engine import SOAREngine

server = FastMCP("Unified Wazuh SOC Platform")
mcp = server
db_session_factory = async_session
wazuh_api_breaker = CircuitBreaker(name="wazuh_api")
wazuh_indexer_breaker = CircuitBreaker(name="wazuh_indexer")


class ToolRequest(BaseModel):
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)


class ToolValidationError(ValueError):
    pass


class WazuhServiceError(RuntimeError):
    pass


def _session_context():
    factory = db_session_factory
    if hasattr(factory, "__aenter__") and hasattr(factory, "__aexit__"):
        return factory
    return factory()


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _jsonable(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value


def _tenant_uuid(tenant_id: str | None) -> uuid.UUID | None:
    if not tenant_id:
        default_tenant = getattr(settings, "api_key_default_tenant", None)
        tenant_id = default_tenant or None
    if not tenant_id:
        try:
            return uuid.UUID(settings.tenant_id)
        except Exception:
            return uuid.UUID("00000000-0000-0000-0000-000000000001")
    try:
        return uuid.UUID(str(tenant_id))
    except Exception:
        return None


def _severity_bucket(level: int | None) -> str:
    if level is None:
        return "unknown"
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def _row(item: Any) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key, value in item.__dict__.items():
        if key.startswith("_"):
            continue
        data[key] = _jsonable(value)
    return data


def _require_param(params: dict[str, Any], name: str) -> Any:
    value = params.get(name)
    if value in (None, ""):
        raise ToolValidationError(f"{name} is required")
    return value


def _first_item(data: Any) -> dict[str, Any] | None:
    if isinstance(data, dict):
        if "data" in data and isinstance(data["data"], dict):
            for key in ("affected_items", "items", "results", "data"):
                value = data["data"].get(key)
                if isinstance(value, list) and value:
                    first = value[0]
                    if isinstance(first, dict):
                        return first
            if data["data"]:
                return data["data"]
        for key in ("affected_items", "items", "results", "data"):
            value = data.get(key)
            if isinstance(value, list) and value:
                first = value[0]
                if isinstance(first, dict):
                    return first
        return data
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0]
    return None


async def _wazuh_api_request(method: str, path: str, *, params: dict[str, Any] | None = None, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
    base_url = settings.wazuh_api_url.rstrip("/")
    timeout = httpx.Timeout(10.0, read=30.0)
    auth = (settings.wazuh_api_user, settings.wazuh_api_password.get_secret_value())

    async with httpx.AsyncClient(verify=settings.wazuh_api_verify_ssl, timeout=timeout) as client:
        try:
            auth_resp = await client.post(
                f"{base_url}/security/user/authenticate",
                auth=auth,
                headers={"Content-Type": "application/json"},
            )
            auth_resp.raise_for_status()
            token = auth_resp.json()["data"]["token"]
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            response = await client.request(
                method,
                f"{base_url}{path}",
                params=params,
                json=json_body,
                headers=headers,
            )
            if response.status_code == 401:
                auth_resp = await client.post(
                    f"{base_url}/security/user/authenticate",
                    auth=auth,
                    headers={"Content-Type": "application/json"},
                )
                auth_resp.raise_for_status()
                token = auth_resp.json()["data"]["token"]
                headers["Authorization"] = f"Bearer {token}"
                response = await client.request(
                    method,
                    f"{base_url}{path}",
                    params=params,
                    json=json_body,
                    headers=headers,
                )
            response.raise_for_status()
            try:
                return response.json()
            except Exception:
                return {"raw": response.text}
        except httpx.HTTPStatusError as exc:
            raise WazuhServiceError(str(exc)) from exc
        except httpx.HTTPError as exc:
            raise WazuhServiceError(str(exc)) from exc


async def _wazuh_indexer_request(index: str, query: dict[str, Any]) -> dict[str, Any]:
    base_url = settings.wazuh_indexer_url.rstrip("/")
    timeout = httpx.Timeout(30.0)
    auth = (settings.wazuh_indexer_user, settings.wazuh_indexer_password.get_secret_value())

    async with httpx.AsyncClient(verify=settings.wazuh_indexer_verify_ssl, timeout=timeout, auth=auth) as client:
        try:
            response = await client.post(
                f"{base_url}/{index}/_search",
                json=query,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            raise WazuhServiceError(str(exc)) from exc
        except httpx.HTTPError as exc:
            raise WazuhServiceError(str(exc)) from exc


def _normalize_hits(data: dict[str, Any]) -> list[dict[str, Any]]:
    hits = data.get("hits", {}) if isinstance(data, dict) else {}
    if isinstance(hits, dict):
        raw_hits = hits.get("hits", [])
    else:
        raw_hits = []
    results: list[dict[str, Any]] = []
    for hit in raw_hits:
        if not isinstance(hit, dict):
            continue
        source = hit.get("_source")
        if isinstance(source, dict):
            results.append(source)
            continue
        results.append(hit)
    return results


async def _breaker_call(breaker: CircuitBreaker, func, *args, **kwargs):
    return await breaker.call(func, *args, **kwargs)


async def _list_alerts(session, limit: int, offset: int, min_level: int, tenant_id: str | None):
    stmt = (
        select(Alert)
        .where(Alert.rule_level >= min_level)
        .order_by(desc(Alert.ingested_at))
        .offset(offset)
        .limit(limit)
    )
    tenant_uuid = _tenant_uuid(tenant_id)
    if tenant_uuid:
        stmt = stmt.where(Alert.tenant_id == tenant_uuid)
    rows = (await session.execute(stmt)).scalars().all()
    return {
        "success": True,
        "count": len(rows),
        "alerts": [
            {
                "id": str(row.id),
                "tenant_id": str(row.tenant_id),
                "rule_id": row.rule_id,
                "rule_description": row.rule_description,
                "rule_level": row.rule_level,
                "rule_groups": row.rule_groups,
                "agent_id": row.agent_id,
                "agent_name": row.agent_name,
                "agent_ip": row.agent_ip,
                "source_ip": row.source_ip,
                "destination_ip": row.destination_ip,
                "user_name": row.user_name,
                "mitre_technique": row.mitre_technique,
                "severity": _severity_bucket(row.rule_level),
                "alert_timestamp": row.alert_timestamp.isoformat() if row.alert_timestamp else None,
                "ingested_at": row.ingested_at.isoformat() if row.ingested_at else None,
            }
            for row in rows
        ],
    }


async def _get_triage(session, alert_id: str, tenant_id: str | None):
    try:
        alert_uuid = uuid.UUID(alert_id)
    except Exception:
        return {"success": False, "error": "Invalid alert_id"}

    stmt = (
        select(AiTriageResult)
        .where(AiTriageResult.alert_id == alert_uuid)
        .order_by(AiTriageResult.created_at.desc())
        .limit(1)
    )
    tenant_uuid = _tenant_uuid(tenant_id)
    if tenant_uuid:
        stmt = stmt.where(AiTriageResult.tenant_id == tenant_uuid)
    triage = (await session.execute(stmt)).scalar_one_or_none()
    if not triage:
        return {"success": False, "error": "Triage result not found"}
    return {
        "success": True,
        "triage": {
            "id": str(triage.id),
            "tenant_id": str(triage.tenant_id),
            "alert_id": str(triage.alert_id) if triage.alert_id else None,
            "model_name": triage.model_name,
            "summary": triage.summary,
            "category": triage.category,
            "severity": triage.severity,
            "confidence": float(triage.confidence) if triage.confidence is not None else None,
            "false_positive_likelihood": float(triage.false_positive_likelihood) if triage.false_positive_likelihood is not None else None,
            "mitre_mapping": _jsonable(triage.mitre_mapping),
            "investigation_steps": _jsonable(triage.investigation_steps),
            "do_not_do": _jsonable(triage.do_not_do),
            "key_entities": _jsonable(triage.key_entities),
            "escalation_required": triage.escalation_required,
            "suggested_soc_action": triage.suggested_soc_action,
            "latency_ms": triage.latency_ms,
            "tokens_input": triage.tokens_input,
            "tokens_output": triage.tokens_output,
            "success": triage.success,
            "error_message": triage.error_message,
            "created_at": triage.created_at.isoformat() if triage.created_at else None,
        },
    }


async def _get_agents(session, limit: int, offset: int, tenant_id: str | None):
    stmt = select(Asset).order_by(desc(Asset.created_at)).offset(offset).limit(limit)
    tenant_uuid = _tenant_uuid(tenant_id)
    if tenant_uuid:
        stmt = stmt.where(Asset.tenant_id == tenant_uuid)
    rows = (await session.execute(stmt)).scalars().all()
    return {
        "success": True,
        "count": len(rows),
        "agents": [
            {
                "id": str(row.id),
                "tenant_id": str(row.tenant_id),
                "agent_id": row.agent_id,
                "agent_name": row.agent_name,
                "agent_ip": row.agent_ip,
                "os_name": row.os_name,
                "os_version": row.os_version,
                "status": row.status,
                "criticality": row.criticality,
                "groups": row.groups,
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            }
            for row in rows
        ],
    }


async def _list_rules(session, limit: int, tenant_id: str | None):
    stmt = (
        select(
            Alert.rule_id.label("rule_id"),
            Alert.rule_description.label("rule_description"),
            Alert.rule_level.label("rule_level"),
            func.count(Alert.id).label("alert_count"),
        )
        .group_by(Alert.rule_id, Alert.rule_description, Alert.rule_level)
        .order_by(desc(func.count(Alert.id)))
        .limit(limit)
    )
    tenant_uuid = _tenant_uuid(tenant_id)
    if tenant_uuid:
        stmt = stmt.where(Alert.tenant_id == tenant_uuid)
    rows = (await session.execute(stmt)).all()
    normalized = []
    for row in rows:
        rule_id = getattr(row, "rule_id", row[0] if len(row) > 0 else None)
        rule_description = getattr(row, "rule_description", row[1] if len(row) > 1 else None)
        rule_level = getattr(row, "rule_level", row[2] if len(row) > 2 else None)
        alert_count = getattr(row, "alert_count", row[3] if len(row) > 3 else 0)
        normalized.append(
            {
                "rule_id": rule_id,
                "rule_description": rule_description,
                "rule_level": rule_level,
                "severity": _severity_bucket(rule_level),
                "alert_count": int(alert_count or 0),
            }
        )
    return {
        "success": True,
        "count": len(normalized),
        "rules": normalized,
    }


async def _get_stats(session, tenant_id: str | None):
    tenant_uuid = _tenant_uuid(tenant_id)

    def scoped(stmt, model):
        if tenant_uuid:
            return stmt.where(model.tenant_id == tenant_uuid)
        return stmt

    alert_total = await session.execute(scoped(select(func.count(Alert.id)), Alert))
    case_total = await session.execute(scoped(select(func.count(Case.id)), Case))
    vuln_total = await session.execute(scoped(select(func.count(Vulnerability.id)), Vulnerability))
    asset_total = await session.execute(scoped(select(func.count(Asset.id)), Asset))
    triage_total = await session.execute(scoped(select(func.count(AiTriageResult.id)), AiTriageResult))
    open_cases = await session.execute(scoped(select(func.count(Case.id)).where(Case.status == "open"), Case))
    critical_vulns = await session.execute(
        scoped(select(func.count(Vulnerability.id)).where(Vulnerability.severity == "critical"), Vulnerability)
    )

    alert_levels = await session.execute(
        scoped(
            select(Alert.rule_level, func.count(Alert.id)).group_by(Alert.rule_level),
            Alert,
        )
    )
    alert_distribution: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for level, count in alert_levels.all():
        alert_distribution[_severity_bucket(level)] += int(count or 0)

    case_severity_rows = await session.execute(
        scoped(select(Case.severity, func.count(Case.id)).group_by(Case.severity), Case)
    )
    case_distribution = {
        (severity or "unknown"): int(count or 0)
        for severity, count in case_severity_rows.all()
    }

    vuln_severity_rows = await session.execute(
        scoped(select(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity), Vulnerability)
    )
    vuln_distribution = {
        (severity or "unknown"): int(count or 0)
        for severity, count in vuln_severity_rows.all()
    }

    return {
        "success": True,
        "counts": {
            "alerts": int(alert_total.scalar_one() or 0),
            "cases": int(case_total.scalar_one() or 0),
            "open_cases": int(open_cases.scalar_one() or 0),
            "vulnerabilities": int(vuln_total.scalar_one() or 0),
            "critical_vulnerabilities": int(critical_vulns.scalar_one() or 0),
            "agents": int(asset_total.scalar_one() or 0),
            "triage_results": int(triage_total.scalar_one() or 0),
        },
        "severity_distribution": {
            "alerts": alert_distribution,
            "cases": case_distribution,
            "vulnerabilities": vuln_distribution,
        },
    }


async def _list_vulnerabilities(
    session,
    limit: int,
    offset: int,
    status: str | None,
    severity: str | None,
    tenant_id: str | None,
):
    stmt = select(Vulnerability).order_by(desc(Vulnerability.risk_score)).offset(offset).limit(limit)
    tenant_uuid = _tenant_uuid(tenant_id)
    if tenant_uuid:
        stmt = stmt.where(Vulnerability.tenant_id == tenant_uuid)
    if status:
        stmt = stmt.where(Vulnerability.status == status)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    rows = (await session.execute(stmt)).scalars().all()
    return {
        "success": True,
        "count": len(rows),
        "vulnerabilities": [
            {
                "id": str(row.id),
                "tenant_id": str(row.tenant_id),
                "cve_id": row.cve_id,
                "cvss_score": float(row.cvss_score) if row.cvss_score is not None else None,
                "severity": row.severity,
                "epss_score": float(row.epss_score) if row.epss_score is not None else None,
                "cisa_kev": row.cisa_kev,
                "risk_score": float(row.risk_score) if row.risk_score is not None else None,
                "package_name": row.package_name,
                "package_version": row.package_version,
                "status": row.status,
                "patch_sla": row.patch_sla.isoformat() if row.patch_sla else None,
                "first_detected_at": row.first_detected_at.isoformat() if row.first_detected_at else None,
                "last_detected_at": row.last_detected_at.isoformat() if row.last_detected_at else None,
            }
            for row in rows
        ],
    }


async def _create_case(
    session,
    title: str,
    description: str | None,
    severity: str,
    category: str | None,
    alert_id: str | None,
    risk_score: float | None,
    tenant_id: str | None,
):
    payload = CaseCreate(
        alert_id=alert_id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        risk_score=risk_score,
    )
    return await api_create_case(
        body=payload,
        db=session,
        _="mcp",
        tenant_id=tenant_id,
    )


async def _load_alert(session, alert_id: str, tenant_id: str | None):
    try:
        alert_uuid = uuid.UUID(alert_id)
    except Exception:
        return None, "Invalid alert_id"
    stmt = select(Alert).where(Alert.id == alert_uuid)
    tenant_uuid = _tenant_uuid(tenant_id)
    if tenant_uuid:
        stmt = stmt.where(Alert.tenant_id == tenant_uuid)
    alert = (await session.execute(stmt)).scalar_one_or_none()
    if not alert:
        return None, "Alert not found"
    return alert, None


async def _load_case(session, case_id: str, tenant_id: str | None):
    try:
        case_uuid = uuid.UUID(case_id)
    except Exception:
        return None, "Invalid case_id"
    stmt = select(Case).where(Case.id == case_uuid)
    tenant_uuid = _tenant_uuid(tenant_id)
    if tenant_uuid:
        stmt = stmt.where(Case.tenant_id == tenant_uuid)
    case = (await session.execute(stmt)).scalar_one_or_none()
    if not case:
        return None, "Case not found"
    return case, None


async def _run_playbook(
    session,
    alert_id: str | None,
    case_id: str | None,
    playbook_id: str | None,
    approved: bool,
    tenant_id: str | None,
):
    if not approved and os.getenv("MCP_RUN_PLAYBOOKS", "").lower() not in {"1", "true", "yes"}:
        return {"success": False, "error": "Playbook execution is gated"}

    alert = None
    if alert_id:
        alert, error = await _load_alert(session, alert_id, tenant_id)
        if error:
            return {"success": False, "error": error}
    elif case_id:
        case, error = await _load_case(session, case_id, tenant_id)
        if error:
            return {"success": False, "error": error}
        if not case.alert_id:
            return {"success": False, "error": "Case has no linked alert"}
        alert, error = await _load_alert(session, str(case.alert_id), tenant_id)
        if error:
            return {"success": False, "error": error}
    else:
        return {"success": False, "error": "alert_id or case_id is required"}

    engine = SOAREngine(session)

    if playbook_id:
        try:
            playbook_uuid = uuid.UUID(playbook_id)
        except Exception:
            return {"success": False, "error": "Invalid playbook_id"}
        stmt = select(Playbook).where(Playbook.id == playbook_uuid)
        tenant_uuid = _tenant_uuid(tenant_id)
        if tenant_uuid:
            stmt = stmt.where(Playbook.tenant_id == tenant_uuid)
        playbook = (await session.execute(stmt)).scalar_one_or_none()
        if not playbook:
            return {"success": False, "error": "Playbook not found"}
        return {"success": True, "result": await engine._execute_playbook(playbook, _row(alert))}

    return {"success": True, "results": await engine.run_for_alert(_row(alert))}


async def _query_indexer(index: str, query: dict[str, Any], size: int = 100) -> dict[str, Any]:
    payload = dict(query)
    payload.setdefault("size", size)
    data = await _breaker_call(wazuh_indexer_breaker, _wazuh_indexer_request, index, payload)
    return {
        "success": True,
        "count": len(_normalize_hits(data)),
        "results": _normalize_hits(data),
        "raw": _jsonable(data),
    }


async def _get_agent_info(agent_id: str) -> dict[str, Any]:
    data = await _breaker_call(wazuh_api_breaker, _wazuh_api_request, "GET", f"/agents/{agent_id}")
    agent = _first_item(data) or data
    return {
        "success": True,
        "agent": _jsonable(agent),
        "raw": _jsonable(data),
    }


async def _list_agents(status: str | None = None, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if status:
        params["status"] = status
    data = await _breaker_call(wazuh_api_breaker, _wazuh_api_request, "GET", "/agents", params=params)
    agents = data.get("data", {}).get("affected_items", []) if isinstance(data, dict) else []
    if status:
        agents = [agent for agent in agents if str(agent.get("status", "")).lower() == status.lower()]
    return {
        "success": True,
        "count": len(agents),
        "agents": _jsonable(agents),
        "raw": _jsonable(data),
    }


async def _manager_status() -> dict[str, Any]:
    data = await _breaker_call(wazuh_api_breaker, _wazuh_api_request, "GET", "/manager/status")
    return {
        "success": True,
        "connected": True,
        "status": _jsonable(data),
    }


async def _search_rules(group: str | None = None, level: int | None = None, description: str | None = None, limit: int = 100) -> dict[str, Any]:
    params: dict[str, Any] = {"limit": limit}
    if group:
        params["group"] = group
    if level is not None:
        params["level"] = level
    if description:
        params["description"] = description
    data = await _breaker_call(wazuh_api_breaker, _wazuh_api_request, "GET", "/rules", params=params)
    rules = data.get("data", {}).get("affected_items", []) if isinstance(data, dict) else []
    if group:
        rules = [rule for rule in rules if group.lower() in str(rule.get("group", "")).lower() or group.lower() in str(rule.get("groups", "")).lower()]
    if level is not None:
        rules = [rule for rule in rules if int(rule.get("level", -1) or -1) == int(level)]
    if description:
        needle = description.lower()
        rules = [rule for rule in rules if needle in str(rule.get("description", "")).lower()]
    return {
        "success": True,
        "count": len(rules),
        "rules": _jsonable(rules),
        "raw": _jsonable(data),
    }


async def _get_syscollector(agent_id: str) -> dict[str, Any]:
    data = await _breaker_call(wazuh_api_breaker, _wazuh_api_request, "GET", f"/syscollector/{agent_id}")
    return {
        "success": True,
        "syscollector": _jsonable(data),
    }


TOOL_DISPATCH = {
    "list_alerts": list_alerts,  # tool wrapper (creates its own DB session)
    "query_indexer": _query_indexer,
    "get_agent_info": _get_agent_info,
    "list_agents": list_agents,  # tool wrapper
    "manager_status": _manager_status,
    "search_rules": _search_rules,
    "get_syscollector": _get_syscollector,
}


@server.tool()
async def list_alerts(
    limit: int = 50,
    offset: int = 0,
    min_level: int = 0,
    tenant_id: str | None = None,
):
    try:
        async with _session_context() as session:
            return await _list_alerts(session, limit, offset, min_level, tenant_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def get_triage(alert_id: str, tenant_id: str | None = None):
    try:
        async with _session_context() as session:
            return await _get_triage(session, alert_id, tenant_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def get_agents(
    limit: int = 50,
    offset: int = 0,
    tenant_id: str | None = None,
):
    try:
        async with _session_context() as session:
            return await _get_agents(session, limit, offset, tenant_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def list_rules(limit: int = 50, tenant_id: str | None = None):
    try:
        async with _session_context() as session:
            return await _list_rules(session, limit, tenant_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def get_stats(tenant_id: str | None = None):
    try:
        async with _session_context() as session:
            return await _get_stats(session, tenant_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def list_vulnerabilities(
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
    severity: str | None = None,
    tenant_id: str | None = None,
):
    try:
        async with _session_context() as session:
            return await _list_vulnerabilities(session, limit, offset, status, severity, tenant_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def create_case(
    title: str,
    description: str | None = None,
    severity: str = "medium",
    category: str | None = None,
    alert_id: str | None = None,
    risk_score: float | None = None,
    tenant_id: str | None = None,
):
    try:
        async with _session_context() as session:
            return await _create_case(
                session,
                title=title,
                description=description,
                severity=severity,
                category=category,
                alert_id=alert_id,
                risk_score=risk_score,
                tenant_id=tenant_id,
            )
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def run_playbook(
    alert_id: str | None = None,
    case_id: str | None = None,
    playbook_id: str | None = None,
    approved: bool = False,
    tenant_id: str | None = None,
):
    try:
        async with _session_context() as session:
            return await _run_playbook(session, alert_id, case_id, playbook_id, approved, tenant_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def query_indexer(index: str = "wazuh-alerts-*", query: dict[str, Any] | None = None, size: int = 100):
    try:
        if query is None:
            raise ToolValidationError("query is required")
        return await _query_indexer(index, query, size=size)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def get_agent_info(agent_id: str):
    try:
        return await _get_agent_info(agent_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def list_agents(
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
    tenant_id: str | None = None,
):
    try:
        return await _list_agents(status=status, limit=limit, offset=offset)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def manager_status():
    try:
        return await _manager_status()
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def search_rules(
    group: str | None = None,
    level: int | None = None,
    description: str | None = None,
    limit: int = 100,
):
    try:
        return await _search_rules(group=group, level=level, description=description, limit=limit)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@server.tool()
async def get_syscollector(agent_id: str):
    try:
        return await _get_syscollector(agent_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


async def call_tool(request: ToolRequest) -> dict[str, Any]:
    handler = TOOL_DISPATCH.get(request.tool)
    if not handler:
        return {"status_code": 404, "success": False, "error": f"Unknown tool: {request.tool}"}
    try:
        result = await handler(**request.params)
        return {"status_code": 200, **result}
    except (ToolValidationError, KeyError, TypeError) as exc:
        return {"status_code": 400, "success": False, "error": str(exc)}
    except (CircuitBreakerOpenError, WazuhServiceError) as exc:
        return {"status_code": 502, "success": False, "error": str(exc)}
    except Exception as exc:
        return {"status_code": 500, "success": False, "error": str(exc)}


app = FastAPI(title="Unified Wazuh SOC Platform - MCP Server")


@app.get("/tools")
async def list_tools():
    return {"tools": list(server.tools.keys()) + list(TOOL_DISPATCH.keys())}


@app.post("/call")
async def call_tool_http(request: Request):
    body = await request.json()
    tool = body.get("tool")
    params = body.get("params", {})
    handler = TOOL_DISPATCH.get(tool)
    if not handler:
        return JSONResponse(status_code=404, content={"success": False, "error": f"Unknown tool: {tool}"})
    try:
        result = await handler(**params)
        return {"success": True, **result}
    except (ToolValidationError, KeyError, TypeError) as exc:
        return JSONResponse(status_code=400, content={"success": False, "error": str(exc)})
    except (CircuitBreakerOpenError, WazuhServiceError) as exc:
        return JSONResponse(status_code=502, content={"success": False, "error": str(exc)})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"success": False, "error": str(exc)})


def main():
    server.run()


if __name__ == "__main__":
    main()
