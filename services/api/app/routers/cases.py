import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from starlette.status import HTTP_404_NOT_FOUND, HTTP_400_BAD_REQUEST

from app.db import get_db
from shared.models.case import Case
from shared.models.analyst_note import AnalystNote
from shared.models.case_event import CaseEvent
from shared.models.case_investigation_step import CaseInvestigationStep
from app.middleware.auth import validate_api_key

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


class CaseCreate(BaseModel):
    alert_id: str | None = None
    title: str
    description: str | None = None
    severity: str = "medium"
    category: str | None = None


class BulkStatusUpdate(BaseModel):
    case_ids: list[str]
    status: str


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
):
    query = select(Case).order_by(desc(Case.created_at))
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
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    query = select(Case).where(Case.id == uid)
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
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    query = select(CaseEvent).where(CaseEvent.case_id == uid).order_by(desc(CaseEvent.created_at))
    if event_type:
        query = query.where(CaseEvent.event_type == event_type)

    count_query = select(CaseEvent.id).where(CaseEvent.case_id == uid)
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
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    query = select(CaseInvestigationStep).where(CaseInvestigationStep.case_id == uid).order_by(CaseInvestigationStep.order)
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
):
    case = Case(
        alert_id=uuid.UUID(body.alert_id) if body.alert_id else None,
        title=body.title,
        description=body.description,
        severity=body.severity,
        category=body.category,
    )
    db.add(case)
    await db.flush()

    event = CaseEvent(
        case_id=case.id,
        tenant_id=case.tenant_id,
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
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    query = select(Case).where(Case.id == uid)
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

    await db.commit()

    return {"status": "success", "case_id": str(case.id)}


@router.post("/{case_id}/notes")
async def add_note(
    case_id: str,
    body: NoteCreate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    note = AnalystNote(
        case_id=uid,
        analyst=body.analyst,
        note=body.note,
        note_type=body.note_type,
    )
    db.add(note)
    await db.flush()

    event = CaseEvent(
        case_id=uid,
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
):
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail="Invalid case ID")

    step = CaseInvestigationStep(
        case_id=uid,
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


@router.post("/bulk-status")
async def bulk_update_status(
    body: BulkStatusUpdate,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(validate_api_key),
):
    updated = 0
    for case_id_str in body.case_ids:
        try:
            uid = uuid.UUID(case_id_str)
        except ValueError:
            continue

        result = await db.execute(select(Case).where(Case.id == uid))
        case = result.scalar_one_or_none()
        if not case:
            continue

        old_status = case.status
        case.status = body.status
        if body.status in ("resolved", "closed"):
            case.closed_at = datetime.now(timezone.utc)

        event = CaseEvent(
            case_id=uid,
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
