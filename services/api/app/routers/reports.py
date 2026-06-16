import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, async_session
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id, require_tenant_uuid
from shared.config import settings
from shared.models.report import Report
from shared.report_generator import ReportGenerator

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportRequest(BaseModel):
    type: str
    format: str = "PDF"
    date_range: str = "last_30d"
    case_id: str | None = None
    framework_id: str | None = None
    filters: dict = Field(default_factory=dict)


def _metadata(report: Report) -> dict:
    return {
        "id": str(report.id),
        "name": report.name,
        "type": report.report_type,
        "format": report.format,
        "parameters": report.parameters,
        "file_size": report.file_size,
        "status": report.status,
        "error_message": report.error_message,
        "created_by": report.created_by,
        "created_at": report.created_at.isoformat(),
        "completed_at": report.completed_at.isoformat()
        if report.completed_at
        else None,
        "expires_at": report.expires_at.isoformat() if report.expires_at else None,
    }


@router.get("")
async def list_reports(
    report_type: str | None = Query(default=None, alias="type"),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(Report).order_by(desc(Report.created_at))
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(Report.tenant_id == tenant_uuid)
    if report_type:
        query = query.where(Report.report_type == report_type)
    if status:
        query = query.where(Report.status == status)
    reports = (await db.execute(query.limit(limit))).scalars().all()
    return {"status": "success", "count": len(reports), "reports": [_metadata(r) for r in reports]}


async def _generate_report_task(report_id: uuid.UUID, payload_dict: dict, api_key_prefix: str):
    """Background task that generates the report file and updates its status."""
    async with async_session() as db:
        report = await db.get(Report, report_id)
        if not report:
            return

        report_type = payload_dict.get("type", "").lower()
        report_format = payload_dict.get("format", "PDF").upper()
        date_range = payload_dict.get("date_range", "last_30d")
        filters = payload_dict.get("filters", {})
        case_id = payload_dict.get("case_id")
        framework_id = payload_dict.get("framework_id")

        try:
            generator = ReportGenerator(db)
            if report_type in ("vulnerability", "technical"):
                html = await generator.generate_vulnerability_report(date_range, filters)
            elif report_type == "case":
                if not case_id:
                    raise ValueError("case_id is required for case reports")
                html = await generator.generate_case_report(case_id)
            elif report_type == "executive":
                html = await generator.generate_executive_summary(date_range)
            elif report_type == "compliance":
                html = await generator.generate_compliance_report(framework_id=framework_id)
            else:
                now = datetime.now(timezone.utc)
                html = await generator.generate_monthly_soc_report(now.month, now.year)

            storage = Path(settings.reports_storage_path)
            storage.mkdir(parents=True, exist_ok=True)
            suffix = "xlsx" if report_format == "EXCEL" else report_format.lower()
            path = storage / f"{report.id}.{suffix}"
            if report_format == "PDF":
                content = generator.html_to_pdf(html)
            elif report_format == "JSON":
                content = json.dumps({"html": html}).encode("utf-8")
            else:
                content = html.encode("utf-8")
            path.write_bytes(content)

            report.file_path = str(path)
            report.file_size = len(content)
            report.status = "completed"
            report.completed_at = datetime.now(timezone.utc)
        except Exception as exc:
            report.status = "failed"
            report.error_message = str(exc)
        await db.commit()


@router.post("", status_code=202)
async def create_report(
    payload: ReportRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    api_key: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    report_type = payload.type.lower()
    report_format = payload.format.upper()
    if report_type not in {"executive", "technical", "vulnerability", "case", "compliance"}:
        raise HTTPException(status_code=400, detail="Unsupported report type")
    if report_format not in {"PDF", "HTML", "JSON", "EXCEL"}:
        raise HTTPException(status_code=400, detail="Unsupported report format")

    now = datetime.now(timezone.utc)
    tenant_uuid = require_tenant_uuid(tenant_id)

    report = Report(
        tenant_id=tenant_uuid,
        name=f"{report_type.title()} Report",
        report_type=report_type,
        format=report_format,
        parameters=payload.model_dump(),
        status="queued",
        created_by=api_key[:8],
        expires_at=now + timedelta(days=settings.report_retention_days),
    )
    db.add(report)
    await db.flush()

    background_tasks.add_task(
        _generate_report_task,
        report.id,
        payload.model_dump(),
        api_key[:8],
    )
    await db.commit()
    return _metadata(report)


@router.get("/{report_id}")
async def get_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(Report).where(Report.id == report_id)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(Report.tenant_id == tenant_uuid)
    report = (await db.execute(query)).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return _metadata(report)


@router.get("/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(Report).where(Report.id == report_id)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(Report.tenant_id == tenant_uuid)
    
    report = (await db.execute(query)).scalar_one_or_none()
    if not report or not report.file_path or not Path(report.file_path).is_file():
        raise HTTPException(status_code=404, detail="Report file not found")
    media_types = {
        "PDF": "application/pdf",
        "HTML": "text/html",
        "JSON": "application/json",
        "EXCEL": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
    return FileResponse(
        report.file_path,
        media_type=media_types.get(report.format, "application/octet-stream"),
        filename=Path(report.file_path).name,
    )


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(Report).where(Report.id == report_id)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(Report.tenant_id == tenant_uuid)
    
    report = (await db.execute(query)).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.file_path:
        Path(report.file_path).unlink(missing_ok=True)
    await db.delete(report)
    await db.commit()
