import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestAgentModels:
    def test_agent_definition_attributes(self):
        from shared.models.agent import AgentDefinition
        assert hasattr(AgentDefinition, "id")
        assert hasattr(AgentDefinition, "name")
        assert hasattr(AgentDefinition, "description")
        assert hasattr(AgentDefinition, "agent_type")
        assert hasattr(AgentDefinition, "config")
        assert hasattr(AgentDefinition, "is_active")
        assert hasattr(AgentDefinition, "created_at")

    def test_agent_run_attributes(self):
        from shared.models.agent import AgentRun
        assert hasattr(AgentRun, "id")
        assert hasattr(AgentRun, "definition_id")
        assert hasattr(AgentRun, "tenant_id")
        assert hasattr(AgentRun, "trigger_type")
        assert hasattr(AgentRun, "trigger_ref")
        assert hasattr(AgentRun, "status")
        assert hasattr(AgentRun, "result_summary")
        assert hasattr(AgentRun, "started_at")
        assert hasattr(AgentRun, "completed_at")

    def test_agent_task_attributes(self):
        from shared.models.agent import AgentTask
        assert hasattr(AgentTask, "id")
        assert hasattr(AgentTask, "run_id")
        assert hasattr(AgentTask, "parent_task_id")
        assert hasattr(AgentTask, "agent_type")
        assert hasattr(AgentTask, "input_data")
        assert hasattr(AgentTask, "output_data")
        assert hasattr(AgentTask, "status")
        assert hasattr(AgentTask, "error")

    def test_agent_run_status_defaults_to_pending(self):
        from shared.models.agent import AgentRun
        from sqlalchemy import inspect
        col = inspect(AgentRun).columns["status"]
        assert col.default.arg == "pending"

    def test_agent_definition_is_active_default(self):
        from shared.models.agent import AgentDefinition
        from sqlalchemy import inspect
        col = inspect(AgentDefinition).columns["is_active"]
        assert col.default.arg is True


class TestOrchestrationEngine:
    @pytest.mark.asyncio
    async def test_create_run_creates_db_record(self):
        from shared.orchestrator.engine import OrchestrationEngine

        run_id = uuid.uuid4()
        defn_id = uuid.uuid4()
        tenant_id = uuid.uuid4()

        mock_run = MagicMock()
        mock_run.id = run_id

        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        engine = OrchestrationEngine(session_factory=None)

        result = await engine.create_run(
            definition_id=defn_id,
            tenant_id=tenant_id,
            trigger_type="manual",
            trigger_ref=None,
            session=mock_session,
        )

        mock_session.add.assert_called_once()
        mock_session.flush.assert_awaited_once()

        added = mock_session.add.call_args[0][0]
        from shared.models.agent import AgentRun
        assert isinstance(added, AgentRun)
        assert added.definition_id == defn_id
        assert added.tenant_id == tenant_id
        assert added.trigger_type == "manual"
        assert added.status == "pending"

    @pytest.mark.asyncio
    async def test_execute_run_handles_missing_run(self):
        from shared.orchestrator.engine import OrchestrationEngine

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        mock_factory = MagicMock()
        mock_factory.return_value = mock_session

        engine = OrchestrationEngine(session_factory=mock_factory)
        await engine.execute_run(uuid.uuid4())

        mock_session.execute.assert_awaited()

    @pytest.mark.asyncio
    async def test_execute_run_handles_empty_task_list(self):
        from shared.orchestrator.engine import OrchestrationEngine
        from shared.models.agent import AgentRun, AgentDefinition

        run_id = uuid.uuid4()
        defn_id = uuid.uuid4()

        mock_run = AgentRun(definition_id=defn_id, trigger_type="manual")
        mock_run.id = run_id

        mock_defn = AgentDefinition(name="test", agent_type="triage")
        mock_defn.id = defn_id
        mock_defn.config = {"tasks": []}

        call_count = 0

        async def execute_side(stmt):
            nonlocal call_count
            r = MagicMock()
            if call_count == 0:
                r.scalar_one_or_none.return_value = mock_run
            else:
                r.scalar_one_or_none.return_value = mock_defn
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
        await engine.execute_run(run_id)

        assert mock_run.status == "completed"
        assert mock_run.result_summary == "Executed 0 task(s)"

    def test_register_agent(self):
        from shared.orchestrator.engine import OrchestrationEngine

        engine = OrchestrationEngine()
        handler = AsyncMock()
        engine.register_agent("test_agent", handler)
        assert engine._registry["test_agent"] is handler

    def test_schema_has_agent_tables(self):
        import pathlib
        schema = (pathlib.Path(__file__).parent.parent / "database" / "schema.sql").read_text()
        assert "CREATE TABLE agent_definitions" in schema
        assert "CREATE TABLE agent_runs" in schema
        assert "CREATE TABLE agent_tasks" in schema
