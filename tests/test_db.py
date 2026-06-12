import pytest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone


def _mock_tenant_id():
    return uuid.UUID('00000000-0000-0000-0000-000000000001')


@pytest.mark.asyncio
async def test_create_alert_model():
    from shared.models.alert import Alert

    alert = Alert(
        tenant_id=_mock_tenant_id(),
        rule_id=100001,
        rule_description="Test alert",
        rule_level=7,
        rule_groups=["test_group"],
        agent_name="test-agent",
        source_ip="10.0.0.1",
        alert_timestamp=datetime.now(timezone.utc),
    )
    assert alert.rule_id == 100001
    assert alert.rule_level == 7


@pytest.mark.asyncio
async def test_create_case_model():
    from shared.models.case import Case

    case = Case(
        tenant_id=_mock_tenant_id(),
        title="Test case",
        severity="medium",
        status="open",
    )
    assert case.status == "open"
    assert case.severity == "medium"


@pytest.mark.asyncio
async def test_create_analyst_note_model():
    from shared.models.analyst_note import AnalystNote

    note = AnalystNote(
        tenant_id=_mock_tenant_id(),
        analyst="test-analyst",
        note="This is a test note",
        note_type="general",
    )
    assert note.analyst == "test-analyst"
    assert note.note_type == "general"


@pytest.mark.asyncio
async def test_create_vulnerability_model():
    from shared.models.vulnerability import Vulnerability

    vuln = Vulnerability(
        tenant_id=_mock_tenant_id(),
        cve_id="CVE-2024-TEST",
        cvss_score=7.5,
        severity="high",
        status="open",
    )
    assert vuln.cve_id == "CVE-2024-TEST"
    assert float(vuln.cvss_score) == 7.5


@pytest.mark.asyncio
async def test_create_audit_log_model():
    from shared.models.audit_log import AuditLog

    log = AuditLog(
        tenant_id=_mock_tenant_id(),
        action="test_action",
        resource_type="test",
        actor="test-user",
        status="success",
    )
    assert log.action == "test_action"
    assert log.status == "success"


@pytest.mark.asyncio
async def test_create_ai_triage_result_model():
    from shared.models.ai_triage_result import AiTriageResult

    triage = AiTriageResult(
        tenant_id=_mock_tenant_id(),
        alert_id=uuid.uuid4(),
        model_name="qwen2.5-coder:7b",
        summary="Test triage",
        category="recon",
        severity="medium",
        confidence=0.85,
        false_positive_likelihood=0.15,
        escalation_required=False,
        success=True,
    )
    assert triage.model_name == "qwen2.5-coder:7b"
    assert triage.confidence == 0.85
    assert triage.category == "recon"


@pytest.mark.asyncio
async def test_create_asset_model():
    from shared.models.asset import Asset

    asset = Asset(
        tenant_id=_mock_tenant_id(),
        agent_id="001",
        agent_name="test-agent",
        agent_ip="10.0.0.1",
        os_name="Linux",
        status="active",
    )
    assert asset.agent_id == "001"
    assert asset.status == "active"


@pytest.mark.asyncio
async def test_create_tenant_model():
    from shared.models.tenant import Tenant

    tenant = Tenant(
        id=_mock_tenant_id(),
        name="Test Tenant",
        slug="test-tenant",
    )
    assert tenant.name == "Test Tenant"
    assert tenant.slug == "test-tenant"


@pytest.mark.asyncio
async def test_model_serialization():
    from shared.models.alert import Alert

    alert = Alert(
        tenant_id=_mock_tenant_id(),
        rule_id=100002,
        rule_description="Serialization test",
        rule_level=12,
        rule_groups=["test", "critical"],
    )
    assert alert.rule_groups == ["test", "critical"]
    assert alert.rule_level == 12


@pytest.mark.asyncio
async def test_model_timestamps():
    from shared.models.case import Case
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    case = Case(
        tenant_id=_mock_tenant_id(),
        title="Timestamp test",
        severity="high",
        status="open",
        created_at=now,
        updated_at=now,
    )
    assert case.created_at == now
    assert case.updated_at == now
