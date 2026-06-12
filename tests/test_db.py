import pytest
from datetime import datetime, timezone


@pytest.mark.asyncio
async def test_db_connection():
    from app.db import async_session

    async with async_session() as session:
        from sqlalchemy import text
        result = await session.execute(text("SELECT 1"))
        assert result.scalar() == 1


@pytest.mark.asyncio
async def test_create_alert():
    from app.db import async_session
    from shared.models.alert import Alert

    async with async_session() as session:
        alert = Alert(
            rule_id=100001,
            rule_description="Test alert",
            rule_level=7,
            rule_groups=["test_group"],
            agent_name="test-agent",
            source_ip="10.0.0.1",
            alert_timestamp=datetime.now(timezone.utc),
        )
        session.add(alert)
        await session.commit()

        assert alert.id is not None
        assert alert.rule_id == 100001


@pytest.mark.asyncio
async def test_create_case():
    from app.db import async_session
    from shared.models.case import Case

    async with async_session() as session:
        case = Case(
            title="Test case",
            severity="medium",
            status="open",
        )
        session.add(case)
        await session.commit()

        assert case.id is not None
        assert case.status == "open"


@pytest.mark.asyncio
async def test_create_analyst_note():
    from app.db import async_session
    from shared.models.analyst_note import AnalystNote

    async with async_session() as session:
        note = AnalystNote(
            analyst="test-analyst",
            note="This is a test note",
            note_type="general",
        )
        session.add(note)
        await session.commit()

        assert note.id is not None
        assert note.analyst == "test-analyst"


@pytest.mark.asyncio
async def test_create_vulnerability():
    from app.db import async_session
    from shared.models.vulnerability import Vulnerability

    async with async_session() as session:
        vuln = Vulnerability(
            cve_id="CVE-2024-TEST",
            cvss_score=7.5,
            severity="high",
            status="open",
        )
        session.add(vuln)
        await session.commit()

        assert vuln.id is not None
        assert vuln.cve_id == "CVE-2024-TEST"
        assert float(vuln.cvss_score) == 7.5


@pytest.mark.asyncio
async def test_create_audit_log():
    from app.db import async_session
    from shared.models.audit_log import AuditLog

    async with async_session() as session:
        log = AuditLog(
            action="test_action",
            resource_type="test",
            actor="test-user",
            status="success",
        )
        session.add(log)
        await session.commit()

        assert log.id is not None
        assert log.action == "test_action"
