import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from starlette.status import HTTP_404_NOT_FOUND

from app.db import get_db
from app.models.case import Case
from app.models.analyst_note import AnalystNote
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

    if body.status is not None:
        case.status = body.status
        if body.status in ("resolved", "closed"):
            case.closed_at = datetime.now(timezone.utc)
    if body.assigned_to is not None:
        case.assigned_to = body.assigned_to
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
    await db.commit()
    await db.refresh(note)

    return {"status": "success", "note_id": str(note.id)}
