import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock
from unittest.mock import patch

import httpx
import pytest

from services.mcp import server as mcp_server


class FakeScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalar_one(self):
        return self._rows[0]


class FakeResult:
    def __init__(self, rows=None):
        self._rows = rows or []

    def scalars(self):
        return FakeScalarResult(self._rows)

    def all(self):
        return self._rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalar_one(self):
        return self._rows[0]


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.committed = False
        self.added = []

    async def execute(self, *args, **kwargs):
        if self.responses:
            return self.responses.pop(0)
        return FakeResult([])

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True


class FakeCtx:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return False


def make_response(status_code: int, json_data: dict | list | None = None, url: str = "https://wazuh.example"):
    request = httpx.Request("GET", url)
    if json_data is None:
        return httpx.Response(status_code, request=request)
    content = mcp_server.json.dumps(json_data).encode("utf-8")
    return httpx.Response(status_code, request=request, content=content, headers={"Content-Type": "application/json"})


def make_httpx_client(*responses):
    client = AsyncMock()
    response_iter = iter(responses)

    async def _post(url, *args, **kwargs):
        if "authenticate" in url:
            return make_response(200, {"data": {"token": "token-1"}}, url=url)
        return next(response_iter)

    async def _request(method, url, *args, **kwargs):
        return next(response_iter)

    client.post.side_effect = _post
    client.request.side_effect = _request
    client.get.side_effect = _request
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return client


@pytest.mark.asyncio
async def test_tools_registered():
    tools = getattr(mcp_server.server, "tools", {})
    assert {
        "list_alerts",
        "get_triage",
        "get_agents",
        "list_rules",
        "get_stats",
        "list_vulnerabilities",
        "create_case",
        "run_playbook",
        "query_indexer",
        "get_agent_info",
        "list_agents",
        "manager_status",
        "search_rules",
        "get_syscollector",
    }.issubset(set(tools))


@pytest.mark.asyncio
async def test_list_alerts_and_triage():
    alert = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        rule_id=1001,
        rule_description="Suspicious login",
        rule_level=10,
        rule_groups=["auth"],
        agent_id="001",
        agent_name="web",
        agent_ip="10.0.0.5",
        source_ip="10.0.0.9",
        destination_ip=None,
        user_name="alice",
        mitre_technique="T1110",
        alert_timestamp=None,
        ingested_at=mcp_server.datetime.now(mcp_server.timezone.utc),
    )
    triage = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=alert.tenant_id,
        alert_id=alert.id,
        model_name="ollama/test",
        summary="Investigate",
        category="auth",
        severity="high",
        confidence=0.91,
        false_positive_likelihood=0.1,
        mitre_mapping=[],
        investigation_steps=[],
        do_not_do=[],
        key_entities=[],
        escalation_required=True,
        suggested_soc_action="Open case",
        latency_ms=42,
        tokens_input=10,
        tokens_output=12,
        success=True,
        error_message=None,
        created_at=mcp_server.datetime.now(mcp_server.timezone.utc),
    )
    session = FakeSession([FakeResult([alert]), FakeResult([triage])])
    alerts = await mcp_server._list_alerts(session, 20, 0, 0, str(alert.tenant_id))
    triage_result = await mcp_server._get_triage(session, str(alert.id), str(alert.tenant_id))
    assert alerts["success"] is True
    assert alerts["count"] == 1
    assert alerts["alerts"][0]["severity"] == "high"
    assert triage_result["success"] is True
    assert triage_result["triage"]["model_name"] == "ollama/test"


@pytest.mark.asyncio
async def test_agents_rules_stats_vulnerabilities():
    tenant_id = uuid.uuid4()
    agent = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        agent_id="001",
        agent_name="server-1",
        agent_ip="10.0.0.10",
        os_name="Ubuntu",
        os_version="22.04",
        status="active",
        criticality=9,
        groups=["prod"],
        last_seen=mcp_server.datetime.now(mcp_server.timezone.utc),
        created_at=mcp_server.datetime.now(mcp_server.timezone.utc),
    )
    vuln = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        cve_id="CVE-2024-0001",
        cvss_score=9.8,
        severity="critical",
        epss_score=0.8,
        cisa_kev=True,
        risk_score=9.1,
        package_name="pkg",
        package_version="1.0",
        status="open",
        patch_sla=mcp_server.datetime.now(mcp_server.timezone.utc).date(),
        first_detected_at=mcp_server.datetime.now(mcp_server.timezone.utc),
        last_detected_at=mcp_server.datetime.now(mcp_server.timezone.utc),
        created_at=mcp_server.datetime.now(mcp_server.timezone.utc),
    )
    alert = SimpleNamespace(rule_id=42, rule_description="Suspicious login", rule_level=10, id=uuid.uuid4(), tenant_id=tenant_id)
    agents = await mcp_server._get_agents(FakeSession([FakeResult([agent])]), 20, 0, str(tenant_id))
    rules = await mcp_server._list_rules(FakeSession([FakeResult([(42, "Suspicious login", 10, 3)])]), 20, str(tenant_id))
    stats = await mcp_server._get_stats(
        FakeSession([
            FakeResult([1]),
            FakeResult([1]),
            FakeResult([1]),
            FakeResult([1]),
            FakeResult([1]),
            FakeResult([1]),
            FakeResult([1]),
            FakeResult([(10, 2)]),
            FakeResult([("critical", 1)]),
            FakeResult([("critical", 1)]),
        ]),
        str(tenant_id),
    )
    vulns = await mcp_server._list_vulnerabilities(FakeSession([FakeResult([vuln])]), 20, 0, None, None, str(tenant_id))
    assert agents["count"] == 1
    assert rules["count"] == 1
    assert stats["counts"]["alerts"] == 1
    assert vulns["count"] == 1


@pytest.mark.asyncio
async def test_create_case_and_gated_playbook(monkeypatch):
    session = FakeSession([])
    monkeypatch.setattr(mcp_server, "api_create_case", AsyncMock(return_value={"status": "success", "case_id": "case-1"}))
    created = await mcp_server._create_case(
        session,
        title="Investigate login spike",
        description="demo",
        severity="high",
        category="auth",
        alert_id=None,
        risk_score=7.5,
        tenant_id=str(uuid.uuid4()),
    )
    gated = await mcp_server._run_playbook(session, None, None, None, False, None)
    assert created["status"] == "success"
    assert gated["success"] is False


@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_query_indexer_returns_results(mock_client):
    client = make_httpx_client(
        make_response(200, {"hits": {"total": {"value": 1}, "hits": [{"_source": {"rule_id": 1, "message": "alert"}}]}}, url="https://indexer.example/wazuh-alerts-*/_search")
    )
    mock_client.return_value = client
    result = await mcp_server.call_tool(
        mcp_server.ToolRequest(
            tool="query_indexer",
            params={"index": "wazuh-alerts-*", "query": {"query": {"match_all": {}}}, "size": 10},
        )
    )
    assert result["status_code"] == 200
    assert result["count"] == 1
    assert result["results"][0]["rule_id"] == 1


@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_list_agents_returns_filtered(mock_client):
    client = make_httpx_client(
        make_response(
            200,
            {
                "data": {
                    "affected_items": [
                        {"id": "001", "status": "active", "name": "agent-1"},
                        {"id": "002", "status": "disconnected", "name": "agent-2"},
                    ]
                }
            },
            url="https://wazuh.example/agents",
        ),
    )
    mock_client.return_value = client
    result = await mcp_server.call_tool(
        mcp_server.ToolRequest(tool="list_agents", params={"status": "active", "limit": 50, "offset": 0})
    )
    assert result["status_code"] == 200
    assert result["count"] == 1
    assert result["agents"][0]["status"] == "active"


@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_manager_status_returns_connected(mock_client):
    client = make_httpx_client(
        make_response(200, {"data": {"status": "running"}}, url="https://wazuh.example/manager/status"),
    )
    mock_client.return_value = client
    result = await mcp_server.call_tool(mcp_server.ToolRequest(tool="manager_status", params={}))
    assert result["status_code"] == 200
    assert result["connected"] is True
    assert result["status"]["data"]["status"] == "running"


@pytest.mark.asyncio
async def test_tool_missing_required_param_returns_400():
    result = await mcp_server.call_tool(mcp_server.ToolRequest(tool="get_agent_info", params={}))
    assert result["status_code"] == 400
    assert result["success"] is False


@pytest.mark.asyncio
@patch("httpx.AsyncClient")
async def test_wazuh_api_unreachable_returns_502(mock_client):
    client = AsyncMock()

    async def _post(url, *args, **kwargs):
        return make_response(200, {"data": {"token": "token-1"}}, url=url)

    async def _request(method, url, *args, **kwargs):
        raise httpx.ConnectError("unreachable", request=httpx.Request(method, url))

    client.post.side_effect = _post
    client.request.side_effect = _request
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    mock_client.return_value = client

    result = await mcp_server.call_tool(mcp_server.ToolRequest(tool="get_agent_info", params={"agent_id": "001"}))
    assert result["status_code"] == 502
    assert result["success"] is False
