import uuid
from datetime import datetime, timezone, timedelta
from typing import Literal
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, text
from pydantic import BaseModel
from starlette.status import HTTP_404_NOT_FOUND, HTTP_400_BAD_REQUEST

from app.db import get_db
from shared.models.case import Case
from shared.models.analyst_note import AnalystNote
from shared.models.case_event import CaseEvent
from shared.models.case_investigation_step import CaseInvestigationStep
from shared.models.ai_triage_result import AiTriageResult
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id, require_tenant_uuid

router = APIRouter(prefix="/cases", tags=["cases"])


class NoteCreate(BaseModel):
    analyst: str
    note: str
    note_type: str = "general"


class CaseUpdate(BaseModel):
    status: str | None = None
    assigned_to: str | None = None
    severity: str | None = None
    false_positive: bool | None = None
    escalation_required: bool | None = None
    risk_score: float | None = None


class CaseCreate(BaseModel):
    alert_id: str | None = None
    title: str
    description: str | None = None
    severity: str = "medium"
    category: str | None = None
    risk_score: float | None = None


def _bound_risk_score(score: float | None) -> float | None:
    if score is None:
        return None
    return min(10.0, max(0.0, float(score)))


class BulkStatusUpdate(BaseModel):
    case_ids: list[str]
    status: Literal["open", "in_progress", "resolved", "closed", "false_positive"]


class StepCreate(BaseModel):
    description: str
    order: int = 0


@router.get("")
async def list_cases(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    query = select(Case).order_by(desc(Case.created_at))
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(Case.tenant_id == tenant_uuid)
    if status:
        query = query.where(Case.status == status)
    if severity:
        query = query.where(Case.severity == severity)
    query = query.limit(limit)
    result = await db.execute(query)
    cases = result.scalars().all()
    return {
        "status": "success",
        "count": len(cases),
        "cases": [
            {
                "id": str(c.id),
                "title": c.title,
                "severity": c.severity,
                "status": c.status,
                "category": c.category,
                "assigned_to": c.assigned_to,
                "false_positive": c.false_positive,
                "escalation_required": c.escalation_required,
                "risk_score": float(c.risk_score) if c.risk_score else None,
                "created_at": c.created_at.isoformat(),
                "updated_at": c.updated_at.isoformat(),
            }
            for c in cases
        ],
    }


@router.get("/{case_id}")
async def get_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    tenant_uuid = require_tenant_uuid(tenant_id)
    query = select(Case).where(Case.id == uid, Case.tenant_id == tenant_uuid)

    result = await db.execute(query)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Case not found")

    notes_query = select(AnalystNote).where(AnalystNote.case_id == uid).order_by(AnalystNote.created_at)
    notes_result = await db.execute(notes_query)
    notes = notes_result.scalars().all()

    return {
        "status": "success",
        "case": {
            "id": str(case.id),
            "alert_id": str(case.alert_id) if case.alert_id else None,
            "title": case.title,
            "description": case.description,
            "severity": case.severity,
            "status": case.status,
            "category": case.category,
            "assigned_to": case.assigned_to,
            "false_positive": case.false_positive,
            "escalation_required": case.escalation_required,
            "risk_score": float(case.risk_score) if case.risk_score else None,
            "created_at": case.created_at.isoformat(),
            "updated_at": case.updated_at.isoformat(),
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
            "notes": [
                {
                    "id": str(n.id),
                    "analyst": n.analyst,
                    "note": n.note,
                    "note_type": n.note_type,
                    "created_at": n.created_at.isoformat(),
                }
                for n in notes
            ],
        },
    }


@router.get("/{case_id}/timeline")
async def get_case_timeline(
    case_id: str,
    event_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    tenant_uuid = require_tenant_uuid(tenant_id)
    query = (
        select(CaseEvent)
        .where(CaseEvent.case_id == uid, CaseEvent.tenant_id == tenant_uuid)
        .order_by(desc(CaseEvent.created_at))
    )
    if event_type:
        query = query.where(CaseEvent.event_type == event_type)

    count_query = select(CaseEvent.id).where(
        CaseEvent.case_id == uid, CaseEvent.tenant_id == tenant_uuid
    )
    if event_type:
        count_query = count_query.where(CaseEvent.event_type == event_type)
    count_result = await db.execute(count_query)
    total = len(count_result.scalars().all())

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()

    return {
        "status": "success",
        "total": total,
        "count": len(events),
        "events": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "actor_id": str(e.actor_id) if e.actor_id else None,
                "actor_name": e.actor_name,
                "old_value": e.old_value,
                "new_value": e.new_value,
                "description": e.description,
                "event_meta": e.event_meta,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    }


@router.get("/{case_id}/steps")
async def list_steps(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    tenant_uuid = require_tenant_uuid(tenant_id)
    query = (
        select(CaseInvestigationStep)
        .where(
            CaseInvestigationStep.case_id == uid,
            CaseInvestigationStep.tenant_id == tenant_uuid,
        )
        .order_by(CaseInvestigationStep.order)
    )

    result = await db.execute(query)
    steps = result.scalars().all()

    return {
        "status": "success",
        "count": len(steps),
        "steps": [
            {
                "id": str(s.id),
                "description": s.description,
                "order": s.order,
                "completed": s.completed,
                "completed_by": str(s.completed_by) if s.completed_by else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "created_at": s.created_at.isoformat(),
            }
            for s in steps
        ],
    }


@router.post("")
async def create_case(
    body: CaseCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    tenant_uuid = require_tenant_uuid(tenant_id)

    case = Case(
        alert_id=uuid.UUID(body.alert_id) if body.alert_id else None,
        title=body.title,
        description=body.description,
        severity=body.severity,
        category=body.category,
        risk_score=_bound_risk_score(body.risk_score),
        tenant_id=tenant_uuid,
    )
    db.add(case)
    await db.flush()

    event = CaseEvent(
        case_id=case.id,
        tenant_id=tenant_uuid,
        event_type="case_created",
        description=f"Case opened: {case.title}",
    )
    db.add(event)

    await db.commit()
    await db.refresh(case)

    return {
        "status": "success",
        "case_id": str(case.id),
    }


@router.patch("/{case_id}")
async def update_case(
    case_id: str,
    body: CaseUpdate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    query = select(Case).where(Case.id == uid)
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(Case.tenant_id == tenant_uuid)
    
    result = await db.execute(query)
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Case not found")

    if body.status is not None and body.status != case.status:
        old_status = case.status
        case.status = body.status
        if body.status in ("resolved", "closed"):
            case.closed_at = datetime.now(timezone.utc)

        event_type = "resolved" if body.status == "resolved" else ("closed" if body.status == "closed" else "status_changed")
        event = CaseEvent(
            case_id=uid,
            tenant_id=case.tenant_id,
            event_type=event_type,
            old_value=old_status,
            new_value=body.status,
            description=f"Status changed: {old_status} → {body.status}",
        )
        db.add(event)

    if body.assigned_to is not None and body.assigned_to != case.assigned_to:
        old_assignee = case.assigned_to
        case.assigned_to = body.assigned_to
        event = CaseEvent(
            case_id=uid,
            tenant_id=case.tenant_id,
            event_type="assigned",
            old_value=old_assignee,
            new_value=body.assigned_to,
            description=f"Assigned to: {body.assigned_to}",
        )
        db.add(event)

    if body.severity is not None:
        case.severity = body.severity
    if body.false_positive is not None:
        case.false_positive = body.false_positive
    if body.escalation_required is not None:
        case.escalation_required = body.escalation_required
    if body.risk_score is not None:
        case.risk_score = _bound_risk_score(body.risk_score)

    await db.commit()

    return {"status": "success", "case_id": str(case.id)}


@router.post("/{case_id}/notes")
async def add_note(
    case_id: str,
    body: NoteCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    tenant_uuid = uuid.UUID(tenant_id) if tenant_id else None

    note = AnalystNote(
        case_id=uid,
        tenant_id=tenant_uuid,
        analyst=body.analyst,
        note=body.note,
        note_type=body.note_type,
    )
    db.add(note)
    await db.flush()

    event = CaseEvent(
        case_id=uid,
        tenant_id=tenant_uuid,
        event_type="note_added",
        actor_name=body.analyst,
        description=f"Note added ({body.note_type})",
        event_meta={"note_type": body.note_type, "note_excerpt": body.note[:200]},
    )
    db.add(event)
    await db.commit()
    await db.refresh(note)

    return {"status": "success", "note_id": str(note.id)}


@router.post("/{case_id}/steps")
async def create_step(
    case_id: str,
    body: StepCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    step = CaseInvestigationStep(
        case_id=uid,
        tenant_id=uuid.UUID(tenant_id) if tenant_id else None,
        description=body.description,
        order=body.order,
    )
    db.add(step)
    await db.commit()
    await db.refresh(step)

    return {"status": "success", "step_id": str(step.id)}


@router.patch("/{case_id}/steps/{step_id}")
async def update_step(
    case_id: str,
    step_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    try:
        case_uid = uuid.UUID(case_id)
        step_uid = uuid.UUID(step_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid ID")

    result = await db.execute(
        select(CaseInvestigationStep).where(
            CaseInvestigationStep.id == step_uid,
            CaseInvestigationStep.case_id == case_uid,
        )
    )
    step = result.scalar_one_or_none()
    if not step:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Step not found")

    step.completed = not step.completed
    if step.completed:
        step.completed_at = datetime.now(timezone.utc)
    else:
        step.completed_at = None
        step.completed_by = None

    await db.commit()

    return {
        "status": "success",
        "step_id": str(step.id),
        "completed": step.completed,
    }


@router.get("/stats/mttr")
async def mttr_statistics(
    days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    total_query = select(func.count(Case.id))
    total_result = await db.execute(total_query)
    total_cases = total_result.scalar()

    open_query = select(func.count(Case.id)).where(Case.status == "open")
    open_result = await db.execute(open_query)
    open_count = open_result.scalar()

    in_progress_query = select(func.count(Case.id)).where(Case.status == "in_progress")
    in_progress_result = await db.execute(in_progress_query)
    in_progress_count = in_progress_result.scalar()

    resolved_query = select(func.count(Case.id)).where(Case.status == "resolved")
    resolved_result = await db.execute(resolved_query)
    resolved_count = resolved_result.scalar()

    closed_query = select(func.count(Case.id)).where(Case.status == "closed")
    closed_result = await db.execute(closed_query)
    closed_count = closed_result.scalar()

    fp_query = select(func.count(Case.id)).where(Case.status == "false_positive")
    fp_result = await db.execute(fp_query)
    fp_count = fp_result.scalar()

    resolved_cases = await db.execute(
        select(Case.created_at, Case.closed_at, Case.status).where(
            Case.status.in_(["resolved", "closed"]),
            Case.closed_at.isnot(None),
            Case.created_at >= cutoff,
        )
    )
    resolved_rows = resolved_cases.all()

    mttr_seconds = []
    mttr_by_day = {}
    for row in resolved_rows:
        delta = (row.closed_at - row.created_at).total_seconds()
        mttr_seconds.append(delta)
        day_key = row.closed_at.strftime("%Y-%m-%d")
        if day_key not in mttr_by_day:
            mttr_by_day[day_key] = []
        mttr_by_day[day_key].append(delta)

    avg_mttr_hours = round((sum(mttr_seconds) / len(mttr_seconds) / 3600), 2) if mttr_seconds else 0
    trend = sorted(
        [{"date": d, "avg_hours": round((sum(v) / len(v) / 3600), 2)} for d, v in mttr_by_day.items()],
        key=lambda x: x["date"],
    )

    return {
        "status": "success",
        "total_cases": total_cases,
        "open": open_count,
        "in_progress": in_progress_count,
        "resolved": resolved_count,
        "closed": closed_count,
        "false_positive": fp_count,
        "avg_mttr_hours": avg_mttr_hours,
        "closed_within_24h": sum(1 for d in mttr_seconds if d <= 86400),
        "closed_within_7d": sum(1 for d in mttr_seconds if d <= 604800),
        "total_resolved": len(mttr_seconds),
        "trend": trend,
    }


@router.get("/stats/mitre-heatmap")
async def mitre_heatmap(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    result = await db.execute(select(AiTriageResult.mitre_mapping))
    rows = result.scalars().all()

    tactic_map = {}
    for row in rows:
        mappings = row if isinstance(row, list) else []
        if not mappings:
            continue
        for m in mappings:
            tactic = m.get("tactic", "Unknown")
            technique = m.get("technique", "Unknown")
            name = m.get("name", technique)
            key = f"{tactic}::{technique}"
            if key not in tactic_map:
                tactic_map[key] = {"tactic": tactic, "technique": technique, "name": name, "count": 0}
            tactic_map[key]["count"] += 1

    tactics_order = ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0010", "TA0011", "TA0040", "TA0043"]

    tactical_groups = {}
    for entry in tactic_map.values():
        t = entry["tactic"]
        if t not in tactical_groups:
            tactical_groups[t] = []
        tactical_groups[t].append(entry)

    sorted_tactics = sorted(tactical_groups.keys(), key=lambda x: tactics_order.index(x) if x in tactics_order else 999)

    return {
        "status": "success",
        "tactics": sorted_tactics,
        "techniques_per_tactic": {t: sorted(tactical_groups[t], key=lambda x: -x["count"]) for t in sorted_tactics},
        "total_techniques": sum(e["count"] for e in tactic_map.values()),
        "unique_techniques": len(tactic_map),
    }


@router.post("/bulk-status")
async def bulk_update_status(
    body: BulkStatusUpdate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
    tenant_id: str | None = Depends(get_tenant_id),
):
    try:
        case_ids = [uuid.UUID(c) for c in body.case_ids]
    except ValueError:
        case_ids = []

    if not case_ids:
        return {"status": "success", "updated": 0}

    query = select(Case).where(Case.id.in_(case_ids))
    if tenant_id:
        tenant_uuid = uuid.UUID(tenant_id)
        query = query.where(Case.tenant_id == tenant_uuid)

    result = await db.execute(query)
    cases = result.scalars().all()

    updated = 0
    for case in cases:
        old_status = case.status
        case.status = body.status
        if body.status in ("resolved", "closed"):
            case.closed_at = datetime.now(timezone.utc)

        event = CaseEvent(
            case_id=case.id,
            tenant_id=case.tenant_id,
            event_type="status_changed",
            old_value=old_status,
            new_value=body.status,
            description=f"Bulk status: {old_status} → {body.status}",
        )
        db.add(event)
        updated += 1

    await db.commit()
    return {"status": "success", "updated": updated}
