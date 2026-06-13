import logging
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from shared.models.alert import Alert
from shared.models.vulnerability import Vulnerability
from shared.models.compliance import ComplianceControl, ComplianceMapping, ComplianceException

logger = logging.getLogger(__name__)


class ComplianceChecker:
    def __init__(self, db: AsyncSession, tenant_id: str | None = None):
        self.db = db
        self.tenant_id = tenant_id

    async def score_framework(self, framework_id: str) -> dict:
        controls = await self._get_controls(framework_id)
        total = len(controls)
        compliant = 0
        warnings = 0
        breaches = 0
        unknown = 0
        control_statuses = []

        for ctrl in controls:
            status, evidence = await self._check_control(ctrl)
            control_statuses.append({
                "id": str(ctrl.id),
                "control_id": ctrl.control_id,
                "title": ctrl.title,
                "description": ctrl.description,
                "status": status,
                "evidence": evidence[:5],
            })
            if status == "compliant":
                compliant += 1
            elif status == "non_compliant":
                breaches += 1
            elif status == "warning":
                warnings += 1
            else:
                unknown += 1

        score = round((compliant / total * 100), 1) if total > 0 else 0.0
        return {
            "total_controls": total,
            "compliant": compliant,
            "warnings": warnings,
            "breaches": breaches,
            "unknown": unknown,
            "score": score,
            "controls": control_statuses,
        }

    async def _get_controls(self, framework_id: str) -> list:
        from uuid import UUID
        result = await self.db.execute(
            select(ComplianceControl).where(ComplianceControl.framework_id == UUID(framework_id))
        )
        return list(result.scalars().all())

    async def _check_control(self, ctrl: ComplianceControl) -> tuple[str, list[dict]]:
        result = await self.db.execute(
            select(ComplianceMapping).where(ComplianceMapping.control_id == ctrl.id)
        )
        mappings = list(result.scalars().all())

        if not mappings:
            return "unknown", []

        evidence = []
        has_violation = False
        has_warning = False

        for mapping in mappings:
            if mapping.rule_id:
                alert_result = await self.db.execute(
                    select(Alert).where(
                        Alert.rule_id == str(mapping.rule_id),
                        Alert.ingested_at >= func.now() - func.make_interval(0, 0, 0, 30),
                    ).limit(5)
                )
                alerts = list(alert_result.scalars().all())
                for a in alerts:
                    evidence.append({
                        "type": "alert",
                        "id": str(a.id),
                        "rule_id": a.rule_id,
                        "rule_description": a.rule_description,
                        "rule_level": a.rule_level,
                        "timestamp": a.ingested_at.isoformat() if a.ingested_at else None,
                    })
                    level = a.rule_level or 0
                    if level >= mapping.rule_level_min:
                        has_violation = True

            if mapping.cve_pattern:
                vuln_result = await self.db.execute(
                    select(Vulnerability).where(
                        func.lower(Vulnerability.cve_id).like(f"%{mapping.cve_pattern.lower()}%"),
                        Vulnerability.status.in_(["open", "reopened"]),
                    ).limit(5)
                )
                vulns = list(vuln_result.scalars().all())
                for v in vulns:
                    evidence.append({
                        "type": "vulnerability",
                        "id": str(v.id),
                        "cve_id": v.cve_id,
                        "risk_score": float(v.risk_score) if v.risk_score else None,
                        "severity": v.severity,
                    })
                    if v.severity in ("critical", "high"):
                        has_violation = True

        exc_result = await self.db.execute(
            select(ComplianceException).where(
                ComplianceException.control_id == ctrl.id,
                ComplianceException.status == "approved",
                func.coalesce(ComplianceException.expires_at, func.now() + func.make_interval(0, 0, 0, 1)) > func.now(),
            )
        )
        active_exception = exc_result.scalar_one_or_none()

        if has_violation:
            if active_exception:
                return "warning", evidence
            return "non_compliant", evidence
        return "compliant", evidence
