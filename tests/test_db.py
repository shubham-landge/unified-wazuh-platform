import uuid
from datetime import datetime, timezone

from shared.models.alert import Alert
from shared.models.analyst_note import AnalystNote
from shared.models.audit_log import AuditLog
from shared.models.base import Base
from shared.models.case import Case
from shared.models.report import Report
from shared.models.vulnerability import Vulnerability

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


def test_expected_tables_are_registered():
    assert {
        "alerts",
        "cases",
        "analyst_notes",
        "vulnerabilities",
        "audit_log",
        "reports",
    }.issubset(Base.metadata.tables)


def test_create_alert_model():
    alert = Alert(
        tenant_id=TENANT_ID,
        rule_id=100001,
        rule_description="Test alert",
        rule_level=7,
        rule_groups=["test_group"],
        agent_name="test-agent",
        source_ip="10.0.0.1",
        alert_timestamp=datetime.now(timezone.utc),
    )
    assert alert.rule_id == 100001
    assert alert.rule_groups == ["test_group"]


def test_create_case_model():
    case = Case(
        tenant_id=TENANT_ID,
        title="Test case",
        severity="medium",
        status="open",
    )
    assert case.title == "Test case"
    assert case.status == "open"


def test_create_analyst_note_model():
    note = AnalystNote(
        tenant_id=TENANT_ID,
        analyst="test-analyst",
        note="This is a test note",
        note_type="general",
    )
    assert note.analyst == "test-analyst"


def test_create_vulnerability_model():
    vulnerability = Vulnerability(
        tenant_id=TENANT_ID,
        cve_id="CVE-2024-TEST",
        cvss_score=7.5,
        severity="high",
        status="open",
    )
    assert vulnerability.cve_id == "CVE-2024-TEST"
    assert float(vulnerability.cvss_score) == 7.5


def test_create_audit_and_report_models():
    audit = AuditLog(
        tenant_id=TENANT_ID,
        action="test_action",
        resource_type="test",
        actor="test-user",
        status="success",
    )
    report = Report(
        tenant_id=TENANT_ID,
        name="Monthly report",
        report_type="executive",
        format="PDF",
        parameters={},
    )
    assert audit.action == "test_action"
    assert report.report_type == "executive"
