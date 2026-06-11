import uuid
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from starlette.status import HTTP_404_NOT_FOUND

from app.db import get_db
from shared.models.vulnerability import Vulnerability
from app.middleware.auth import validate_api_key

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("")
async def list_vulnerabilities(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    cve_id: str | None = Query(default=None),
    asset_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    query = select(Vulnerability).order_by(desc(Vulnerability.risk_score))

    if status:
        query = query.where(Vulnerability.status == status)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if cve_id:
        query = query.where(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
    if asset_id:
        try:
            uid = uuid.UUID(asset_id)
            query = query.where(Vulnerability.asset_id == uid)
        except ValueError:
            pass

    query = query.limit(limit)
    result = await db.execute(query)
    vulns = result.scalars().all()

    return {
        "status": "success",
        "count": len(vulns),
        "vulnerabilities": [
            {
                "id": str(v.id),
                "cve_id": v.cve_id,
                "cvss_score": float(v.cvss_score) if v.cvss_score else None,
                "severity": v.severity,
                "epss_score": float(v.epss_score) if v.epss_score else None,
                "cisa_kev": v.cisa_kev,
                "risk_score": float(v.risk_score) if v.risk_score else None,
                "package_name": v.package_name,
                "package_version": v.package_version,
                "status": v.status,
                "patch_sla": v.patch_sla.isoformat() if v.patch_sla else None,
                "assigned_owner": v.assigned_owner,
                "asset_id": str(v.asset_id) if v.asset_id else None,
                "first_detected_at": v.first_detected_at.isoformat(),
                "last_detected_at": v.last_detected_at.isoformat(),
            }
            for v in vulns
        ],
    }


@router.get("/{vuln_id}")
async def get_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    try:
        uid = uuid.UUID(vuln_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid vulnerability ID")

    query = select(Vulnerability).where(Vulnerability.id == uid)
    result = await db.execute(query)
    vuln = result.scalar_one_or_none()

    if not vuln:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Vulnerability not found")

    return {
        "status": "success",
        "vulnerability": {
            "id": str(vuln.id),
            "cve_id": vuln.cve_id,
            "cve_description": vuln.cve_description,
            "cvss_score": float(vuln.cvss_score) if vuln.cvss_score else None,
            "severity": vuln.severity,
            "epss_score": float(vuln.epss_score) if vuln.epss_score else None,
            "cisa_kev": vuln.cisa_kev,
            "exploitability": vuln.exploitability,
            "risk_score": float(vuln.risk_score) if vuln.risk_score else None,
            "package_name": vuln.package_name,
            "package_version": vuln.package_version,
            "status": vuln.status,
            "patch_available": vuln.patch_available,
            "patch_sla": vuln.patch_sla.isoformat() if vuln.patch_sla else None,
            "assigned_owner": vuln.assigned_owner,
            "remediation_notes": vuln.remediation_notes,
            "exception_approved_by": vuln.exception_approved_by,
            "exception_reason": vuln.exception_reason,
            "first_detected_at": vuln.first_detected_at.isoformat(),
            "last_detected_at": vuln.last_detected_at.isoformat(),
            "asset_id": str(vuln.asset_id) if vuln.asset_id else None,
        },
    }
