import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.db import get_db
from app.routers import approvals
from app.middleware.auth_jwt import get_current_user
from app.middleware.tenant_enforce import get_tenant_id
from app.middleware.auth import validate_api_key
from shared.models.approval import ApprovalRequest
from shared.auth import TokenData
from services.worker.app.approval_worker import ApprovalWorker

@pytest.fixture
def mock_db():
    db = MagicMock()
    db.execute = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db

@pytest.fixture
def app(mock_db):
    fastapi_app = FastAPI()
    fastapi_app.include_router(approvals.router)
    fastapi_app.dependency_overrides[get_db] = lambda: mock_db
    fastapi_app.dependency_overrides[get_current_user] = lambda: TokenData(
        user_id="test_user_id",
        email="admin@company.com",
        role="admin",
        permissions=["admin"]
    )
    fastapi_app.dependency_overrides[get_tenant_id] = lambda: "00000000-0000-0000-0000-000000000001"
    fastapi_app.dependency_overrides[validate_api_key] = lambda: "api-key"
    return fastapi_app

@pytest.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c

def test_approval_request_model_attributes():
    req_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    expires = datetime.now(timezone.utc)
    req = ApprovalRequest(
        id=req_id,
        tenant_id=tenant_id,
        requested_by="system",
        action_type="block_ip",
        action_params={"ip": "1.1.1.1"},
        target_ref="alert-1",
        rationale="malicious ip",
        risk_level="high",
        status="pending",
        expires_at=expires
    )
    assert req.id == req_id
    assert req.tenant_id == tenant_id
    assert req.requested_by == "system"
    assert req.action_type == "block_ip"
    assert req.action_params == {"ip": "1.1.1.1"}
    assert req.target_ref == "alert-1"
    assert req.rationale == "malicious ip"
    assert req.risk_level == "high"
    assert req.status == "pending"
    assert req.expires_at == expires

@pytest.mark.asyncio
async def test_create_approval_request(client, mock_db):
    payload = {
        "requested_by": "system",
        "action_type": "block_ip",
        "action_params": {"ip": "1.1.1.1"},
        "target_ref": "alert-123",
        "rationale": "blocking bad IP",
        "risk_level": "medium",
        "expires_in_seconds": 3600
    }
    resp = await client.post("/approvals", json=payload)
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"
    assert "approval_id" in resp.json()
    mock_db.add.assert_called_once()
    mock_db.commit.assert_called_once()

@pytest.mark.asyncio
async def test_review_approval_request(client, mock_db):
    req_id = uuid.uuid4()
    mock_request = ApprovalRequest(
        id=req_id,
        tenant_id=uuid.uuid4(),
        requested_by="system",
        action_type="block_ip",
        action_params={"ip": "1.1.1.1"},
        target_ref="alert-1",
        rationale="malicious ip",
        risk_level="high",
        status="pending",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    
    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = mock_request
    mock_db.execute.return_value = mock_res
    
    payload = {
        "status": "approved",
        "comment": "Approved by supervisor"
    }
    resp = await client.put(f"/approvals/{req_id}/review", json=payload)
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"
    assert mock_request.status == "approved"
    assert mock_request.reviewed_by == "admin@company.com"
    assert mock_request.review_comment == "Approved by supervisor"
    mock_db.commit.assert_called_once()

@pytest.mark.asyncio
async def test_approval_worker_expiry_loop():
    worker = ApprovalWorker()
    mock_session = AsyncMock()
    mock_context = MagicMock()
    mock_context.__aenter__.return_value = mock_session
    worker.session_factory = MagicMock(return_value=mock_context)
    
    await worker.check_expired_approvals()
    mock_session.execute.assert_called_once()
    mock_session.commit.assert_called_once()

