import uuid
from datetime import datetime, timezone, timedelta
from typing import Literal
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from pydantic import BaseModel

from app.db import get_db
from app.middleware.auth_jwt import get_current_user
from app.middleware.auth import validate_api_key
from app.middleware.tenant_enforce import get_tenant_id
from shared.config import settings
from shared.models.approval import ApprovalRequest
from shared.auth import TokenData

router = APIRouter(prefix="/approvals", tags=["approvals"])

_DEFAULT_LIMIT = settings.api_default_page_limit

class ApprovalCreate(BaseModel):
    requested_by: str
    action_type: str
    action_params: dict
    target_ref: str | None = None
    rationale: str
    risk_level: str
    expires_in_seconds: int = 3600

class ReviewRequest(BaseModel):
    status: Literal["approved", "rejected"]
    comment: str | None = None

@router.get("")
async def list_approvals(
    status: str | None = Query(default=None),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(get_current_user),
    tenant_id: str | None = Depends(get_tenant_id)
):
    query = select(ApprovalRequest).order_by(desc(ApprovalRequest.created_at))
    if status:
        query = query.where(ApprovalRequest.status == status)
    if tenant_id:
        try:
            t_uid = uuid.UUID(tenant_id)
            query = query.where(ApprovalRequest.tenant_id == t_uid)
        except ValueError:
            pass
    query = query.limit(limit)
    result = await db.execute(query)
    approvals = result.scalars().all()
    return {
        "status": "success",
        "count": len(approvals),
        "approvals": [
            {
                "id": str(a.id),
                "tenant_id": str(a.tenant_id),
                "requested_by": a.requested_by,
                "action_type": a.action_type,
                "action_params": a.action_params,
                "target_ref": a.target_ref,
                "rationale": a.rationale,
                "risk_level": a.risk_level,
                "status": a.status,
                "reviewed_by": a.reviewed_by,
                "review_comment": a.review_comment,
                "expires_at": a.expires_at.isoformat(),
                "created_at": a.created_at.isoformat(),
                "updated_at": a.updated_at.isoformat()
            }
            for a in approvals
        ]
    }

@router.post("")
async def create_approval(
    body: ApprovalCreate,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(get_tenant_id),
    _: str = Depends(validate_api_key)
):
    t_uid = uuid.UUID(tenant_id)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=body.expires_in_seconds)
    req = ApprovalRequest(
        tenant_id=t_uid,
        requested_by=body.requested_by,
        action_type=body.action_type,
        action_params=body.action_params,
        target_ref=body.target_ref,
        rationale=body.rationale,
        risk_level=body.risk_level,
        expires_at=expires_at
    )
    db.add(req)
    await db.commit()
    await db.refresh(req)
    return {
        "status": "success",
        "approval_id": str(req.id)
    }

@router.put("/{approval_id}/review")
async def review_approval(
    approval_id: str,
    body: ReviewRequest,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(get_current_user)
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    try:
        a_uid = uuid.UUID(approval_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid approval ID")
    
    query = select(ApprovalRequest).where(ApprovalRequest.id == a_uid)
    res = await db.execute(query)
    req = res.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    if req.status != "pending":
        raise HTTPException(status_code=400, detail="Only pending requests can be reviewed")
    
    if req.expires_at <= datetime.now(timezone.utc):
        req.status = "expired"
        await db.commit()
        raise HTTPException(status_code=400, detail="Approval request has expired")

    req.status = body.status
    req.reviewed_by = current_user.email
    req.review_comment = body.comment
    await db.commit()
    return {
        "status": "success",
        "approval_id": str(req.id),
        "new_status": req.status
    }

@router.get("/pending")
async def pending_approvals_count(
    db: AsyncSession = Depends(get_db),
    tenant_id: str | None = Depends(get_tenant_id)
):
    query = select(func.count()).select_from(ApprovalRequest).where(ApprovalRequest.status == "pending")
    if tenant_id:
        try:
            t_uid = uuid.UUID(tenant_id)
            query = query.where(ApprovalRequest.tenant_id == t_uid)
        except ValueError:
            pass
    res = await db.execute(query)
    count = res.scalar() or 0
    return {"count": count}
