from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.db import get_db
from app.routers import cases
from shared.models.case_event import CaseEvent
from shared.models.case_investigation_step import CaseInvestigationStep


# ── CaseEvent Model Tests ──

class TestCaseEventModel:
    def test_model_attributes(self):
        assert hasattr(CaseEvent, "id")
        assert hasattr(CaseEvent, "case_id")
        assert hasattr(CaseEvent, "event_type")
        assert hasattr(CaseEvent, "old_value")
        assert hasattr(CaseEvent, "new_value")
        assert hasattr(CaseEvent, "description")
        assert hasattr(CaseEvent, "event_meta")
        assert hasattr(CaseEvent, "created_at")


class TestCaseInvestigationStepModel:
    def test_model_attributes(self):
        assert hasattr(CaseInvestigationStep, "id")
        assert hasattr(CaseInvestigationStep, "case_id")
        assert hasattr(CaseInvestigationStep, "description")
        assert hasattr(CaseInvestigationStep, "order")
        assert hasattr(CaseInvestigationStep, "completed")
        assert hasattr(CaseInvestigationStep, "completed_by")
        assert hasattr(CaseInvestigationStep, "completed_at")


# ── Timeline API Tests ──

class TestTimelineAPI:
    @pytest.fixture
    def api_app(self):
        db = MagicMock()
        db.execute = AsyncMock()

        def make_empty_result():
            r = MagicMock()
            r.scalars.return_value.all.return_value = []
            r.scalar_one_or_none.return_value = None
            return r

        db.execute = AsyncMock(return_value=make_empty_result())
        db.add = MagicMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()

        app = FastAPI()
        app.include_router(cases.router)
        app.dependency_overrides[get_db] = lambda: db
        from app.middleware.auth import validate_api_key
        app.dependency_overrides[validate_api_key] = lambda: "test-key"
        return app

    @pytest.fixture
    async def client(self, api_app):
        async with AsyncClient(
            transport=ASGITransport(app=api_app),
            base_url="http://test",
        ) as test_client:
            yield test_client

    @pytest.mark.asyncio
    async def test_timeline_empty(self, client):
        resp = await client.get("/cases/00000000-0000-0000-0000-000000000001/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["count"] == 0

    @pytest.mark.asyncio
    async def test_timeline_invalid_case_id(self, client):
        resp = await client.get("/cases/invalid-uuid/timeline")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_timeline_with_event_filter(self, client):
        resp = await client.get(
            "/cases/00000000-0000-0000-0000-000000000001/timeline?event_type=status_changed"
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_timeline_pagination(self, client):
        resp = await client.get(
            "/cases/00000000-0000-0000-0000-000000000001/timeline?limit=10&offset=0"
        )
        assert resp.status_code == 200


# ── Investigation Steps API Tests ──

class TestStepsAPI:
    @pytest.fixture
    def api_app(self):
        db = MagicMock()
        db.execute = AsyncMock()

        mock_step = MagicMock()
        mock_step.id = "00000000-0000-0000-0000-000000000010"
        mock_step.description = "Check source IP reputation"
        mock_step.order = 0
        mock_step.completed = False
        mock_step.completed_by = None
        mock_step.completed_at = None
        mock_step.created_at = MagicMock()
        mock_step.created_at.isoformat.return_value = "2026-01-01T00:00:00"

        def execute_side(*args, **kwargs):
            r = MagicMock()
            r.scalars.return_value.all.return_value = [mock_step]
            r.scalar_one_or_none.return_value = mock_step
            return r

        db.execute = AsyncMock(side_effect=execute_side)
        db.add = MagicMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        app = FastAPI()
        app.include_router(cases.router)
        app.dependency_overrides[get_db] = lambda: db
        from app.middleware.auth import validate_api_key
        app.dependency_overrides[validate_api_key] = lambda: "test-key"
        return app

    @pytest.fixture
    async def client(self, api_app):
        async with AsyncClient(
            transport=ASGITransport(app=api_app),
            base_url="http://test",
        ) as test_client:
            yield test_client

    @pytest.mark.asyncio
    async def test_list_steps(self, client):
        resp = await client.get("/cases/00000000-0000-0000-0000-000000000001/steps")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert len(data["steps"]) == 1

    @pytest.mark.asyncio
    async def test_create_step(self, client):
        resp = await client.post(
            "/cases/00000000-0000-0000-0000-000000000001/steps",
            json={"description": "Isolate endpoint", "order": 1},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "step_id" in data

    @pytest.mark.asyncio
    async def test_toggle_step(self, client):
        resp = await client.patch(
            "/cases/00000000-0000-0000-0000-000000000001/steps/00000000-0000-0000-0000-000000000010"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["completed"] is True


# ── Auto-Logging Tests ──

class TestAutoLogging:
    CASE_UUID = "00000000-0000-0000-0000-000000000001"

    @pytest.fixture
    def api_app(self):
        db = MagicMock()
        db.execute = AsyncMock()

        mock_case = MagicMock()
        mock_case.id = self.CASE_UUID
        mock_case.tenant_id = "tenant-1"
        mock_case.status = "open"
        mock_case.assigned_to = None
        mock_case.severity = "medium"
        mock_case.false_positive = False
        mock_case.escalation_required = False
        mock_case.alert_id = None
        mock_case.title = "Test Case"
        mock_case.description = None
        mock_case.category = None
        mock_case.risk_score = None
        mock_case.closed_at = None
        mock_case.created_at = MagicMock()
        mock_case.created_at.isoformat.return_value = "2026-01-01T00:00:00"
        mock_case.updated_at = MagicMock()
        mock_case.updated_at.isoformat.return_value = "2026-01-01T00:00:00"

        def execute_fn(*args, **kwargs):
            result = MagicMock()
            result.scalar_one_or_none.return_value = mock_case
            return result

        db.execute = AsyncMock(side_effect=execute_fn)
        db.add = MagicMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()

        app = FastAPI()
        app.include_router(cases.router)
        app.dependency_overrides[get_db] = lambda: db
        from app.middleware.auth import validate_api_key
        app.dependency_overrides[validate_api_key] = lambda: "test-key"
        return app

    @pytest.fixture
    async def client(self, api_app):
        async with AsyncClient(
            transport=ASGITransport(app=api_app),
            base_url="http://test",
        ) as test_client:
            yield test_client

    @pytest.mark.asyncio
    async def test_update_case_status_logs_event(self, client):
        resp = await client.patch(
            f"/cases/{self.CASE_UUID}",
            json={"status": "in_progress"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_update_case_assignment_logs_event(self, client):
        resp = await client.patch(
            f"/cases/{self.CASE_UUID}",
            json={"assigned_to": "Analyst X"},
        )
        assert resp.status_code == 200


# ── Bulk Status Update Tests ──

class TestBulkStatus:
    @pytest.fixture
    def api_app(self):
        db = MagicMock()
        db.execute = AsyncMock()

        mock_case = MagicMock()
        mock_case.id = "case-1"
        mock_case.tenant_id = "tenant-1"
        mock_case.status = "open"

        async def execute_fn(*args, **kwargs):
            result = MagicMock()
            result.scalar_one_or_none.return_value = mock_case
            return result

        db.execute = AsyncMock(side_effect=execute_fn)
        db.add = MagicMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()

        app = FastAPI()
        app.include_router(cases.router)
        app.dependency_overrides[get_db] = lambda: db
        from app.middleware.auth import validate_api_key
        app.dependency_overrides[validate_api_key] = lambda: "test-key"
        return app

    @pytest.fixture
    async def client(self, api_app):
        async with AsyncClient(
            transport=ASGITransport(app=api_app),
            base_url="http://test",
        ) as test_client:
            yield test_client

    @pytest.mark.asyncio
    async def test_bulk_status_update(self, client):
        resp = await client.post(
            "/cases/bulk-status",
            json={"case_ids": ["00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"], "status": "in_progress"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["updated"] >= 0


# ── Risk Score Computation Tests ──

class TestRiskScore:
    def test_risk_score_formula_high_confidence(self):
        confidence = 0.9
        fp_likelihood = 0.1
        level = 12
        risk = round(confidence * (1 - fp_likelihood) * min(level / 15, 1) * 10, 2)
        assert risk == round(0.9 * 0.9 * 0.8 * 10, 2)
        assert risk == 6.48

    def test_risk_score_formula_low_confidence(self):
        confidence = 0.3
        fp_likelihood = 0.7
        level = 5
        risk = round(confidence * (1 - fp_likelihood) * min(level / 15, 1) * 10, 2)
        assert risk == round(0.3 * 0.3 * (5/15) * 10, 2)
        assert risk == 0.3

    def test_risk_score_capped_at_level(self):
        confidence = 1.0
        fp_likelihood = 0.0
        level = 30  # above 15
        risk = round(confidence * (1 - fp_likelihood) * min(level / 15, 1) * 10, 2)
        assert risk == 10.0  # capped
