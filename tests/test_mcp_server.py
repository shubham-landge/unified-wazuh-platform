import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

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


@pytest.mark.asyncio
async def test_tools_registered():
    tools = getattr(mcp_server.server, "tools", {})
    assert {"list_alerts", "get_triage", "get_agents", "list_rules", "get_stats", "list_vulnerabilities", "create_case", "run_playbook"}.issubset(set(tools))


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
