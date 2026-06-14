import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from shared.orchestrator.engine import OrchestrationEngine, HandlerContext
from shared.orchestrator import handlers
from shared.models.agent import AgentRun, AgentDefinition, AgentTask
from shared.models.case import Case


class TestAgentHandlerRegistration:
    def test_worker_registers_all_handlers(self):
        from services.worker.app.agent_worker import AgentWorker

        worker = AgentWorker()
        assert len(worker.orchestrator._registry) == 8
        for name in ["triage", "ti_enrich", "ueba_check", "case_create", "soar_run", "notify", "review", "lead"]:
            assert name in worker.orchestrator._registry


class TestOrchestratorOutputChaining:
    @pytest.mark.asyncio
    async def test_previous_output_merged_into_next_task_input(self):
        run_id = uuid.uuid4()
        defn_id = uuid.uuid4()

        mock_run = AgentRun(definition_id=defn_id, trigger_type="manual")
        mock_run.id = run_id

        handler = AsyncMock()
        handler.side_effect = [
            {"verdict": "malicious"},
            {"case_id": "abc"},
        ]

        defn = AgentDefinition(name="chain", agent_type="lead")
        defn.id = defn_id
        defn.config = {
            "tasks": [
                {"agent_type": "triage", "input": {"alert_id": "1"}},
                {"agent_type": "case_create", "input": {"title": "Case"}},
            ]
        }

        call_count = 0

        async def execute_side(stmt):
            nonlocal call_count
            r = MagicMock()
            if call_count == 0:
                r.scalar_one_or_none.return_value = mock_run
            else:
                r.scalar_one_or_none.return_value = defn
            call_count += 1
            return r

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=execute_side)
        mock_session.flush = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_factory = MagicMock()
        mock_factory.return_value = mock_session

        engine = OrchestrationEngine(session_factory=mock_factory)
        engine.register_agent("triage", handler)
        engine.register_agent("case_create", handler)

        await engine.execute_run(run_id)

        assert mock_run.status == "completed"
        calls = handler.await_args_list
        assert len(calls) == 2
        # First task gets its own input
        assert calls[0][0][0]["alert_id"] == "1"
        # Second task inherits previous output plus its own input
        second_input = calls[1][0][0]
        assert second_input["verdict"] == "malicious"
        assert second_input["title"] == "Case"


class TestTriageHandler:
    @pytest.mark.asyncio
    async def test_triage_returns_verdict(self):
        alert = MagicMock()
        alert.id = uuid.uuid4()
        alert.title = "Suspicious login"
        alert.description = "Login from unusual IP"
        alert.severity = "high"

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = alert
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_run = MagicMock()
        mock_task = MagicMock()
        mock_task.id = uuid.uuid4()
        ctx = HandlerContext(session=mock_session, run=mock_run, task=mock_task)

        with patch("shared.orchestrator.handlers.get_provider") as mock_get_provider:
            provider = AsyncMock()
            provider.analyze = AsyncMock(
                return_value={
                    "success": True,
                    "verdict": "suspicious",
                    "severity": "high",
                    "confidence": 0.8,
                    "summary": "Unusual login",
                    "recommended_action": "Investigate",
                }
            )
            mock_get_provider.return_value = provider

            result = await handlers.triage({"alert_id": str(alert.id)}, ctx)

        assert result["verdict"] == "suspicious"
        assert result["confidence"] == 0.8
        assert result["alert_id"] == str(alert.id)


class TestCaseCreateHandler:
    @pytest.mark.asyncio
    async def test_case_create_inserts_case(self):
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        added = []
        mock_session.add = lambda obj: added.append(obj)

        mock_run = MagicMock()
        mock_run.tenant_id = uuid.uuid4()
        mock_task = MagicMock()
        mock_task.id = uuid.uuid4()
        ctx = HandlerContext(session=mock_session, run=mock_run, task=mock_task)

        result = await handlers.case_create(
            {"title": "Phishing alert", "description": "Suspicious email", "severity": "high"},
            ctx,
        )

        assert len(added) == 1
        case = added[0]
        assert isinstance(case, Case)
        assert case.title == "Phishing alert"
        assert case.severity == "high"
        assert case.status == "open"
        assert result["case_id"] == str(case.id)


class TestLeadHandler:
    @pytest.mark.asyncio
    async def test_lead_creates_child_tasks(self):
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        added = []
        mock_session.add = lambda obj: added.append(obj)

        mock_run = MagicMock()
        mock_run.id = uuid.uuid4()
        mock_task = MagicMock()
        mock_task.id = uuid.uuid4()
        ctx = HandlerContext(session=mock_session, run=mock_run, task=mock_task)

        with patch("shared.orchestrator.handlers.get_provider") as mock_get_provider:
            provider = AsyncMock()
            provider.analyze = AsyncMock(
                return_value={
                    "success": True,
                    "plan": [
                        {"agent_type": "ti_enrich", "input": {"iocs": ["1.2.3.4"]}, "description": "Enrich IOC"},
                        {"agent_type": "case_create", "input": {"title": "IOC case"}, "description": "Create case"},
                    ],
                }
            )
            mock_get_provider.return_value = provider

            result = await handlers.lead({"objective": "Investigate IOC"}, ctx)

        assert len(result["plan"]) == 2
        child_tasks = [obj for obj in added if isinstance(obj, AgentTask)]
        assert len(child_tasks) == 2
        assert all(t.parent_task_id == mock_task.id for t in child_tasks)
        assert all(t.status == "pending" for t in child_tasks)
