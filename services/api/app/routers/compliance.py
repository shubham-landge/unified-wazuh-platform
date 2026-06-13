import uuid
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from starlette.status import HTTP_404_NOT_FOUND, HTTP_400_BAD_REQUEST

from app.db import get_db
from app.middleware.auth import validate_api_key
from app.middleware.auth_jwt import get_current_user
from app.middleware.tenant_enforce import get_tenant_id
from shared.auth import TokenData
from shared.models.compliance import ComplianceFramework, ComplianceControl, ComplianceMapping, ComplianceException
from shared.compliance_checker import ComplianceChecker

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/frameworks")
async def list_frameworks(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(ComplianceFramework).order_by(ComplianceFramework.name)
    if tenant_id:
        import uuid
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(ComplianceFramework.tenant_id == tenant_uuid)
    
    result = await db.execute(query)
    frameworks = result.scalars().all()
    return {
        "status": "success",
        "count": len(frameworks),
        "frameworks": [
            {
                "id": str(f.id),
                "name": f.name,
                "version": f.version,
                "description": f.description,
                "total_controls": f.total_controls,
                "score": float(f.score) if f.score else 0.0,
            }
            for f in frameworks
        ],
    }


@router.get("/frameworks/{framework_id}/score")
async def framework_score(
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(framework_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid framework ID")

    query = select(ComplianceFramework).where(ComplianceFramework.id == uid)
    if tenant_id:
        import uuid
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(ComplianceFramework.tenant_id == tenant_uuid)
    
    result = await db.execute(query)
    framework = result.scalar_one_or_none()
    if not framework:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Framework not found")

    checker = ComplianceChecker(db)
    score_data = await checker.score_framework(framework_id)

    return {
        "status": "success",
        "framework": {
            "id": str(framework.id),
            "name": framework.name,
            "version": framework.version,
        },
        "score": score_data,
    }


class ExceptionRequest(BaseModel):
    control_id: str
    reason: str
    duration_days: int = 30


@router.post("/exceptions")
async def request_exception(
    body: ExceptionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(get_current_user),
):
    try:
        ctrl_uid = uuid.UUID(body.control_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid control ID")

    result = await db.execute(select(ComplianceControl).where(ComplianceControl.id == ctrl_uid))
    control = result.scalar_one_or_none()
    if not control:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Control not found")

    exc = ComplianceException(
        control_id=ctrl_uid,
        tenant_id=current_user.tenant_id,
        reason=body.reason,
        requested_by=current_user.user_id,
        duration_days=body.duration_days,
        expires_at=datetime.now(timezone.utc) + timedelta(days=body.duration_days),
    )
    db.add(exc)
    await db.commit()
    await db.refresh(exc)

    return {"status": "success", "exception_id": str(exc.id)}


@router.get("/exceptions")
async def list_exceptions(
    status: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(ComplianceException).order_by(ComplianceException.created_at.desc())
    if tenant_id:
        import uuid
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(ComplianceException.tenant_id == tenant_uuid)
    
    if status:
        query = query.where(ComplianceException.status == status)
    result = await db.execute(query)
    excs = result.scalars().all()
    return {
        "status": "success",
        "count": len(excs),
        "exceptions": [
            {
                "id": str(e.id),
                "control_id": str(e.control_id),
                "reason": e.reason,
                "status": e.status,
                "duration_days": e.duration_days,
                "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in excs
        ],
    }


@router.patch("/exceptions/{exc_id}")
async def update_exception(
    exc_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(exc_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid exception ID")

    query = select(ComplianceException).where(ComplianceException.id == uid)
    if tenant_id:
        import uuid
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(ComplianceException.tenant_id == tenant_uuid)
    
    result = await db.execute(query)
    exc = result.scalar_one_or_none()
    if not exc:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Exception not found")

    if "status" in body:
        exc.status = body["status"]
    if "approved_by" in body:
        try:
            exc.approved_by = uuid.UUID(body["approved_by"])
        except ValueError:
            pass
    exc.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {"status": "success", "exception_id": exc_id}


@router.post("/frameworks/{framework_id}/seed")
async def seed_framework(
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(framework_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid framework ID")

    query = select(ComplianceFramework).where(ComplianceFramework.id == uid)
    if tenant_id:
        import uuid
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(ComplianceFramework.tenant_id == tenant_uuid)
    
    result = await db.execute(query)
    framework = result.scalar_one_or_none()
    if not framework:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Framework not found")

    seeds = {
        "SOC2": {
            "controls": [
                {"id": "CC6.1", "title": "Logical Access Control", "desc": "Restricts logical access to authorized personnel", "cat": "Access Control", "sev": "high", "rule_ids": [550, 5710]},
                {"id": "CC6.3", "title": "User Registration and Revocation", "desc": "Manages logical access through user lifecycle audits", "cat": "Access Control", "sev": "high", "rule_ids": [5710]},
                {"id": "CC7.1", "title": "Vulnerability Management", "desc": "Identifies and remediates security vulnerabilities", "cat": "Monitoring", "sev": "critical", "cve_pattern": "CVE"},
                {"id": "CC7.2", "title": "Security Monitoring", "desc": "Monitors infrastructure for unauthorized access", "cat": "Monitoring", "sev": "high", "rule_ids": [550, 802, 807]},
            ]
        },
        "PCI-DSS": {
            "controls": [
                {"id": "Req 6.2", "title": "Patch Installation", "desc": "Installs critical security patches within timelines", "cat": "Patch Mgmt", "sev": "critical", "cve_pattern": "CVE"},
                {"id": "Req 10.2", "title": "Audit Logging", "desc": "Stores and audits detailed event logs", "cat": "Logging", "sev": "high", "rule_ids": [802, 807]},
                {"id": "Req 11.3", "title": "Vulnerability Scanning", "desc": "Runs regular internal and external scans", "cat": "Scanning", "sev": "high", "cve_pattern": "CVE"},
            ]
        },
        "HIPAA": {
            "controls": [
                {"id": "164.312(a)(1)", "title": "Unique User Identification", "desc": "Assigns unique identifiers for ePHI access", "cat": "Access Control", "sev": "high", "rule_ids": [5710]},
                {"id": "164.312(c)(1)", "title": "ePHI Authentication", "desc": "Verifies ePHI has not been altered", "cat": "Integrity", "sev": "critical", "rule_ids": [550]},
                {"id": "164.312(e)(1)", "title": "Transmission Security", "desc": "Protects ePHI in transit", "cat": "Network", "sev": "high", "rule_ids": [807]},
            ]
        }
    }

    fw_name = framework.name.upper()
    if fw_name not in seeds:
        raise HTTPException(status_code=400, detail=f"No seed data for framework {framework.name}")

    data = seeds[fw_name]
    count = 0
    for ctrl_data in data["controls"]:
        existing = await db.execute(
            select(ComplianceControl).where(
                ComplianceControl.framework_id == uid,
                ComplianceControl.control_id == ctrl_data["id"],
            )
        )
        if existing.scalar_one_or_none():
            continue

        control = ComplianceControl(
            framework_id=uid,
            control_id=ctrl_data["id"],
            title=ctrl_data["title"],
            description=ctrl_data["desc"],
            category=ctrl_data.get("cat"),
            severity=ctrl_data.get("sev"),
        )
        db.add(control)
        await db.flush()

        for rid in ctrl_data.get("rule_ids", []):
            db.add(ComplianceMapping(
                control_id=control.id,
                rule_id=rid,
                description=f"Mapped from rule {rid}",
            ))
        if ctrl_data.get("cve_pattern"):
            db.add(ComplianceMapping(
                control_id=control.id,
                cve_pattern=ctrl_data["cve_pattern"],
                description=f"CVEs matching {ctrl_data['cve_pattern']}",
            ))
        count += 1

    framework.total_controls = (
        await db.execute(
            select(func.count(ComplianceControl.id)).where(ComplianceControl.framework_id == uid)
        )
    ).scalar() or 0
    await db.commit()

    return {"status": "success", "seeded": count}
