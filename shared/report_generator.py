import json
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select

from shared.connectors.llm_provider import get_provider
from shared.models.alert import Alert
from shared.models.analyst_note import AnalystNote
from shared.models.case import Case
from shared.models.vulnerability import Vulnerability
from shared.models.compliance import ComplianceFramework, ComplianceControl, ComplianceException

TEMPLATES_DIR = (
    Path(__file__).parent.parent
    / "services"
    / "dashboard"
    / "templates"
    / "reports"
)
PROMPT_PATHS = (
    Path(__file__).parent.parent
    / "services"
    / "api"
    / "app"
    / "prompts"
    / "system_soc_triage.md",
    Path("/app/app/prompts/system_soc_triage.md"),
)


class ReportGenerator:
    def __init__(self, db=None, templates_dir: Path | None = None):
        self.db = db
        self.templates = Environment(
            loader=FileSystemLoader(str(templates_dir or TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    async def generate_vulnerability_report(
        self,
        date_range: str = "last_30d",
        filters: dict | None = None,
    ) -> str:
        db = self._require_db()
        start = self._date_range_start(date_range)
        query = select(Vulnerability).where(Vulnerability.created_at >= start)
        filters = filters or {}
        if filters.get("severity"):
            query = query.where(Vulnerability.severity == filters["severity"])
        if filters.get("status"):
            query = query.where(Vulnerability.status == filters["status"])
        result = await db.execute(query)
        vulnerabilities = result.scalars().all()

        today = datetime.now(timezone.utc).date()
        patched = [
            vuln for vuln in vulnerabilities if vuln.status in {"patched", "verified"}
        ]
        patched_in_sla = sum(
            1
            for vuln in patched
            if not vuln.patch_sla
            or (vuln.patched_at and vuln.patched_at.date() <= vuln.patch_sla)
        )
        context = {
            "date_range": date_range,
            "vulnerabilities": vulnerabilities,
            "critical_count": sum(v.severity == "critical" for v in vulnerabilities),
            "high_count": sum(v.severity == "high" for v in vulnerabilities),
            "total_patched": len(patched),
            "patched_in_sla": patched_in_sla,
            "sla_compliance_pct": round(
                patched_in_sla / len(patched) * 100, 1
            )
            if patched
            else 0.0,
            "overdue_count": sum(
                bool(v.patch_sla and v.patch_sla < today)
                and v.status not in {"patched", "verified", "false_positive"}
                for v in vulnerabilities
            ),
        }
        return self.templates.get_template("vulnerability_report.html").render(**context)

    async def generate_case_report(self, case_id: str) -> str:
        db = self._require_db()
        case_result = await db.execute(select(Case).where(Case.id == case_id))
        case = case_result.scalar_one_or_none()
        if case is None:
            raise ValueError(f"Case {case_id} not found")
        notes_result = await db.execute(
            select(AnalystNote)
            .where(AnalystNote.case_id == case.id)
            .order_by(AnalystNote.created_at)
        )
        notes = notes_result.scalars().all()
        case_data = self._serialize(
            case,
            (
                "id",
                "alert_id",
                "title",
                "description",
                "severity",
                "status",
                "category",
                "assigned_to",
                "risk_score",
                "created_at",
                "closed_at",
            ),
        )
        case_data["notes"] = [
            self._serialize(
                note,
                ("id", "analyst", "note", "note_type", "created_at"),
            )
            for note in notes
        ]
        return self.templates.get_template("case_report.html").render(case=case_data)

    async def generate_monthly_soc_report(self, month: int, year: int) -> str:
        db = self._require_db()
        start = datetime(year, month, 1, tzinfo=timezone.utc)
        end = (
            datetime(year + 1, 1, 1, tzinfo=timezone.utc)
            if month == 12
            else datetime(year, month + 1, 1, tzinfo=timezone.utc)
        )
        alerts = (
            await db.execute(
                select(Alert).where(Alert.ingested_at >= start, Alert.ingested_at < end)
            )
        ).scalars().all()
        cases = (
            await db.execute(
                select(Case).where(Case.created_at >= start, Case.created_at < end)
            )
        ).scalars().all()
        vulnerabilities = (
            await db.execute(
                select(Vulnerability).where(
                    Vulnerability.created_at >= start,
                    Vulnerability.created_at < end,
                )
            )
        ).scalars().all()

        alert_severity = Counter(self._alert_severity(a.rule_level) for a in alerts)
        case_status = Counter(case.status for case in cases)
        vuln_severity = Counter(vuln.severity or "none" for vuln in vulnerabilities)
        context = {
            "month_name": start.strftime("%B"),
            "year": year,
            "total_alerts": len(alerts),
            "total_cases": len(cases),
            "resolved_cases": case_status["resolved"] + case_status["closed"],
            "critical_alerts": alert_severity["critical"],
            "high_alerts": alert_severity["high"],
            "medium_alerts": alert_severity["medium"],
            "low_alerts": alert_severity["low"],
            "avg_triage_latency": 0.0,
            "case_status_breakdown": dict(case_status),
            "vulnerability_severity_breakdown": dict(vuln_severity),
            "critical_avg_time": 0,
            "critical_sla_pct": 0,
            "high_avg_time": 0,
            "high_sla_pct": 0,
            "medium_avg_time": 0,
            "medium_sla_pct": 0,
        }
        return self.templates.get_template("monthly_soc_report.html").render(**context)

    async def generate_executive_summary(self, date_range: str = "last_30d") -> str:
        db = self._require_db()
        start = self._date_range_start(date_range)
        alerts = (
            await db.execute(select(Alert).where(Alert.ingested_at >= start))
        ).scalars().all()
        cases = (
            await db.execute(select(Case).where(Case.created_at >= start))
        ).scalars().all()
        vulnerabilities = (
            await db.execute(
                select(Vulnerability).where(Vulnerability.created_at >= start)
            )
        ).scalars().all()
        prompt_path = next((path for path in PROMPT_PATHS if path.exists()), None)
        prompt = (
            prompt_path.read_text()
            if prompt_path
            else "Write a concise defensive SOC executive summary."
        )
        statistics = {
            "date_range": date_range,
            "alerts": len(alerts),
            "cases": len(cases),
            "vulnerabilities": len(vulnerabilities),
            "critical_alerts": sum(
                self._alert_severity(alert.rule_level) == "critical"
                for alert in alerts
            ),
            "critical_vulnerabilities": sum(
                vulnerability.severity == "critical"
                for vulnerability in vulnerabilities
            ),
        }
        result = await get_provider().analyze(
            system_prompt=prompt,
            user_prompt=json.dumps(statistics),
        )
        summary = result.get("summary") or result.get("error") or "No summary available."
        context = {
            "date": date.today().isoformat(),
            "incident_id": "SOC-" + datetime.now(timezone.utc).strftime("%Y%m%d"),
            "severity": "critical"
            if statistics["critical_alerts"]
            or statistics["critical_vulnerabilities"]
            else "medium",
            "status": "Generated",
            "duration": date_range,
            "affected_assets": "See detailed findings",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "impact": result.get("impact", "Review the summarized security activity."),
            "actions": result.get("investigation_steps", []),
            "recommendations": result.get(
                "recommendations",
                [result.get("recommended_soc_action", "Continue SOC monitoring.")],
            ),
        }
        return self.templates.get_template("executive_summary.html").render(**context)

    async def generate_compliance_report(
        self,
        framework_id: str | None = None,
    ) -> str:
        db = self._require_db()
        from shared.compliance_checker import ComplianceChecker
        checker = ComplianceChecker(db)

        if framework_id:
            frameworks_data = await db.execute(
                select(ComplianceFramework).where(ComplianceFramework.id == framework_id)
            )
            frameworks = [frameworks_data.scalar_one_or_none()] if frameworks_data.scalar_one_or_none() else []
        else:
            result = await db.execute(select(ComplianceFramework))
            frameworks = list(result.scalars().all())

        sections = []
        for fw in frameworks:
            score_data = await checker.score_framework(str(fw.id))
            exc_result = await db.execute(
                select(ComplianceException, ComplianceControl.control_id)
                .join(ComplianceControl, ComplianceException.control_id == ComplianceControl.id)
                .where(
                    ComplianceException.status == "approved",
                    ComplianceControl.framework_id == fw.id,
                )
            )
            exc_rows = exc_result.all()
            exc_data = [
                {"control_id": row.control_id, "reason": row.ComplianceException.reason,
                 "expires_at": row.ComplianceException.expires_at.isoformat() if row.ComplianceException.expires_at else None}
                for row in exc_rows
            ]
            sections.append({
                "framework_name": fw.name,
                "framework_version": fw.version,
                "score": score_data["score"],
                "total_controls": score_data["total_controls"],
                "compliant": score_data["compliant"],
                "warnings": score_data["warnings"],
                "breaches": score_data["breaches"],
                "controls": score_data["controls"],
                "exceptions": exc_data,
            })

        context = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sections": sections,
        }
        if sections:
            context.update(sections[0])
        return self.templates.get_template("compliance_report.html").render(**context)

    @staticmethod
    def html_to_pdf(html: str) -> bytes:
        try:
            from weasyprint import HTML

            return HTML(string=html).write_pdf()
        except Exception:
            return html.encode("utf-8")

    def _require_db(self):
        if self.db is None:
            raise RuntimeError("ReportGenerator requires an AsyncSession")
        return self.db

    @staticmethod
    def _date_range_start(date_range: str) -> datetime:
        days = {
            "last_24h": 1,
            "last_7d": 7,
            "last_30d": 30,
            "last_90d": 90,
        }.get(date_range, 30)
        return datetime.now(timezone.utc) - timedelta(days=days)

    @staticmethod
    def _alert_severity(level: int | None) -> str:
        level = level or 0
        if level >= 12:
            return "critical"
        if level >= 10:
            return "high"
        if level >= 7:
            return "medium"
        return "low"

    @staticmethod
    def _serialize(item, fields: tuple[str, ...]) -> dict:
        data = {}
        for field in fields:
            value = getattr(item, field, None)
            if isinstance(value, (datetime, date)):
                value = value.isoformat()
            elif value is not None and not isinstance(
                value, (str, int, float, bool, list, dict)
            ):
                value = str(value)
            data[field] = value
        return data
