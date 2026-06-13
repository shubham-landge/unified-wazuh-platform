from datetime import date, datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.report_generator import ReportGenerator


def _result(items, one=None):
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    result.scalar_one_or_none.return_value = one
    return result


@pytest.mark.asyncio
async def test_generate_vulnerability_report_html():
    vulnerability = SimpleNamespace(
        cve_id="CVE-2024-12345",
        severity="critical",
        cvss_score=9.8,
        epss_score=0.8,
        cisa_kev=True,
        package_name="openssl",
        patch_sla=date.today(),
        patched_at=None,
        status="open",
    )
    db = MagicMock()
    db.execute = AsyncMock(return_value=_result([vulnerability]))

    html = await ReportGenerator(db).generate_vulnerability_report("last_30d", {})

    assert "CVE-2024-12345" in html
    assert "openssl" in html
    assert "Vulnerability Assessment Report" in html


@pytest.mark.asyncio
async def test_generate_case_report_html():
    now = datetime.now(timezone.utc)
    case = SimpleNamespace(
        id="case-1",
        alert_id="alert-1",
        title="Suspicious process",
        description="PowerShell activity",
        severity="high",
        status="closed",
        category="malware",
        assigned_to="alice",
        risk_score=8.2,
        created_at=now,
        closed_at=now,
    )
    note = SimpleNamespace(
        id="note-1",
        analyst="alice",
        note="Endpoint contained",
        note_type="resolution",
        created_at=now,
    )
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[_result([], one=case), _result([note])])

    html = await ReportGenerator(db).generate_case_report("case-1")

    assert "Suspicious process" in html
    assert "Endpoint contained" in html


@pytest.mark.asyncio
async def test_generate_monthly_report_aggregates_counts():
    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[
            _result([SimpleNamespace(rule_level=13), SimpleNamespace(rule_level=8)]),
            _result(
                [
                    SimpleNamespace(status="closed"),
                    SimpleNamespace(status="open"),
                ]
            ),
            _result([SimpleNamespace(severity="critical")]),
        ]
    )

    html = await ReportGenerator(db).generate_monthly_soc_report(6, 2026)

    assert "June 2026" in html
    assert "Alerts Ingested" in html
    assert ">2<" in html


@pytest.mark.asyncio
async def test_generate_executive_summary_uses_llm():
    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[
            _result([SimpleNamespace(rule_level=13)]),
            _result([]),
            _result([SimpleNamespace(severity="critical")]),
        ]
    )
    provider = MagicMock()
    provider.analyze = AsyncMock(
        return_value={
            "summary": "Critical activity requires leadership attention.",
            "investigation_steps": ["Validate containment"],
            "recommended_soc_action": "Prioritize remediation",
        }
    )
    with patch("shared.report_generator.get_provider", return_value=provider):
        html = await ReportGenerator(db).generate_executive_summary("last_7d")

    assert "Critical activity requires leadership attention." in html
    assert "Validate containment" in html


def test_html_to_pdf_falls_back_to_html_bytes():
    with patch.dict("sys.modules", {"weasyprint": None}):
        result = ReportGenerator.html_to_pdf("<h1>Report</h1>")

    assert result == b"<h1>Report</h1>"
