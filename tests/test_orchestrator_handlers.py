import uuid
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from shared.orchestrator.engine import OrchestrationEngine, HandlerContext
from shared.orchestrator import handlers
from shared.models.agent import AgentRun, AgentDefinition, AgentTask
from shared.models.alert_dedup import AlertIncident
from shared.models.approval import ApprovalRequest
from shared.models.case import Case
from shared.models.case_event import CaseEvent
from shared.models.soar import SoarExecution, SoarPlaybook


class TestAgentHandlerRegistration:
    def test_worker_registers_all_handlers(self):
        from services.worker.app.agent_worker import AgentWorker

        worker = AgentWorker()
        assert len(worker.orchestrator._registry) == 12
        for name in [
            "triage", "ti_enrich", "ueba_check", "case_create", "soar_run",
            "notify", "review", "lead", "correlation", "response_planner",
            "policy_guard", "evidence_pack",
        ]:
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

        defn = AgentDefinition(name="full", agent_type="test", autonomy_level="full")
        defn.id = uuid.uuid4()

        # First execute: _check_existing_approval -> None; second: _load_definition -> full agent
        none_result = MagicMock()
        none_result.scalar_one_or_none.return_value = None
        defn_result = MagicMock()
        defn_result.scalar_one_or_none.return_value = defn
        mock_session.execute = AsyncMock(side_effect=[none_result, defn_result])

        mock_run = MagicMock()
        mock_run.tenant_id = uuid.uuid4()
        mock_run.definition_id = defn.id
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


class TestPolicyGuardHandler:
    @pytest.fixture
    def _ctx(self):
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        added = []
        mock_session.add = lambda obj: added.append(obj)
        mock_session._added = added
        mock_run = MagicMock()
        mock_run.tenant_id = uuid.uuid4()
        mock_run.definition_id = uuid.uuid4()
        mock_task = MagicMock()
        mock_task.agent_type = "policy_guard"
        return HandlerContext(session=mock_session, run=mock_run, task=mock_task)

    @pytest.mark.asyncio
    async def test_read_only_autonomy_denies(self, _ctx):
        defn = AgentDefinition(name="ro", agent_type="test", autonomy_level="read-only")
        defn.id = _ctx.run.definition_id
        none_result = MagicMock()
        none_result.scalar_one_or_none.return_value = None
        defn_result = MagicMock()
        defn_result.scalar_one_or_none.return_value = defn
        _ctx.session.execute = AsyncMock(side_effect=[none_result, defn_result])

        out = await handlers.policy_guard(
            {"action_type": "soar_run", "target_ref": "alert-1", "rationale": "test"}, _ctx
        )
        assert out["approved"] is False
        assert "read-only" in out["reason"].lower()

    @pytest.mark.asyncio
    async def test_full_autonomy_approves(self, _ctx):
        defn = AgentDefinition(name="full", agent_type="test", autonomy_level="full")
        defn.id = _ctx.run.definition_id
        none_result = MagicMock()
        none_result.scalar_one_or_none.return_value = None
        defn_result = MagicMock()
        defn_result.scalar_one_or_none.return_value = defn
        _ctx.session.execute = AsyncMock(side_effect=[none_result, defn_result])

        out = await handlers.policy_guard(
            {"action_type": "soar_run", "target_ref": "alert-1", "rationale": "test"}, _ctx
        )
        assert out["approved"] is True
        assert out["reason"] == "Agent has full autonomy"

    @pytest.mark.asyncio
    async def test_approval_autonomy_creates_request(self, _ctx):
        defn = AgentDefinition(name="approval", agent_type="test", autonomy_level="approval")
        defn.id = _ctx.run.definition_id
        none_result = MagicMock()
        none_result.scalar_one_or_none.return_value = None
        defn_result = MagicMock()
        defn_result.scalar_one_or_none.return_value = defn
        _ctx.session.execute = AsyncMock(side_effect=[none_result, defn_result])

        out = await handlers.policy_guard(
            {
                "action_type": "case_create",
                "target_ref": "alert-1",
                "rationale": "Create case for alert",
                "risk_level": "high",
            },
            _ctx,
        )
        assert out["approved"] is False
        assert out["status"] == "pending"
        assert "approval_id" in out
        # ApprovalRequest should have been queued
        assert any(isinstance(a, ApprovalRequest) for a in _ctx.session._added)

    @pytest.mark.asyncio
    async def test_existing_approval_short_circuits(self, _ctx):
        approval = ApprovalRequest(
            tenant_id=_ctx.run.tenant_id,
            requested_by="test",
            action_type="soar_run",
            action_params={},
            target_ref="alert-1",
            rationale="prior",
            risk_level="medium",
            status="approved",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        approval.id = uuid.uuid4()
        result = MagicMock()
        result.scalar_one_or_none.return_value = approval
        _ctx.session.execute = AsyncMock(return_value=result)

        out = await handlers.policy_guard(
            {"action_type": "soar_run", "target_ref": "alert-1", "rationale": "test"}, _ctx
        )
        assert out["approved"] is True
        assert out["approval_id"] == str(approval.id)


class TestCorrelationHandler:
    @pytest.mark.asyncio
    async def test_correlation_creates_incident(self):
        alert = MagicMock()
        alert.id = uuid.uuid4()
        alert.source_ip = "10.0.0.1"
        alert.user_name = "alice"
        alert.mitre_technique = "T1078"
        alert.agent_id = None
        alert.rule_id = 123
        alert.rule_description = "Login anomaly"
        alert.severity = "high"
        alert.rule_level = 12
        alert.source_type = "endpoint"
        alert.created_at = datetime.now(timezone.utc)

        alert_result = MagicMock()
        alert_result.scalar_one_or_none.return_value = alert

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=[alert_result])
        mock_session.flush = AsyncMock()
        added = []
        mock_session.add = lambda obj: added.append(obj)

        mock_run = MagicMock()
        mock_run.tenant_id = uuid.uuid4()
        mock_task = MagicMock()
        ctx = HandlerContext(session=mock_session, run=mock_run, task=mock_task)

        mock_incident = MagicMock(spec=AlertIncident)
        mock_incident.id = uuid.uuid4()
        mock_incident.alert_count = 1
        mock_incident.cross_domain = False
        mock_incident.source_domains = ["endpoint"]
        mock_incident.kill_chain_stage = "unknown"
        mock_incident.stage_history = []
        mock_incident.sla_due_at = None
        mock_incident.severity = "high"
        mock_incident.status = "open"

        mock_evidence = MagicMock()
        mock_evidence.few_shot_examples = []
        mock_evidence.to_dict.return_value = {"enriched_at": "2026-01-01T00:00:00"}

        with patch("shared.orchestrator.handlers.stitch_incident", new_callable=AsyncMock) as mock_stitch:
            with patch("shared.orchestrator.handlers.enrich_incident", new_callable=AsyncMock) as mock_enrich:
                with patch("shared.orchestrator.handlers.compute_killchain_stage", new_callable=AsyncMock) as mock_kc:
                    mock_stitch.return_value = mock_incident
                    mock_enrich.return_value = mock_evidence
                    mock_kc.return_value = "unknown"

                    result = await handlers.correlation({"alert_ids": [str(alert.id)]}, ctx)

                    assert result["incident_id"] is not None
                    assert result["alert_count"] == 1
                    assert result["severity"] == "high"
                    assert result["cross_domain"] == False
                    assert result["source_domains"] == ["endpoint"]
                    mock_stitch.assert_awaited_once()
                    mock_enrich.assert_awaited_once()


class TestResponsePlannerHandler:
    @pytest.mark.asyncio
    async def test_response_planner_creates_draft_playbook(self):
        alert = MagicMock()
        alert.id = uuid.uuid4()
        alert.rule_description = "Suspicious login"
        alert.severity = "high"
        alert.rule_level = 12
        alert.source_ip = "10.0.0.1"
        alert.user_name = "alice"
        alert.agent_name = "win-1"
        alert.mitre_tactic = "TA0001"
        alert.mitre_technique = "T1078"

        alert_result = MagicMock()
        alert_result.scalar_one_or_none.return_value = alert
        triage_result = MagicMock()
        triage_result.scalar_one_or_none.return_value = None
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=[alert_result, triage_result])
        mock_session.flush = AsyncMock()
        added = []
        mock_session.add = lambda obj: added.append(obj)

        mock_run = MagicMock()
        mock_run.tenant_id = uuid.uuid4()
        mock_task = MagicMock()
        mock_task.agent_type = "response_planner"
        ctx = HandlerContext(session=mock_session, run=mock_run, task=mock_task)

        with patch("shared.orchestrator.handlers.get_provider") as mock_get_provider:
            provider = AsyncMock()
            provider.analyze = AsyncMock(
                return_value={
                    "success": True,
                    "steps": ["Isolate host", "Reset password"],
                    "investigation_plan": "Verify account compromise",
                    "estimated_effort": "30m",
                    "required_tools": ["EDR", "AD"],
                }
            )
            mock_get_provider.return_value = provider

            result = await handlers.response_planner({"alert_id": str(alert.id)}, ctx)

        assert result["draft"] is True
        assert result["steps"] == ["Isolate host", "Reset password"]
        assert len(added) == 1
        assert isinstance(added[0], SoarPlaybook)
        assert added[0].enabled is False


class TestEvidencePackHandler:
    @pytest.mark.asyncio
    async def test_evidence_pack_builds_bundle(self):
        case = MagicMock()
        case.id = uuid.uuid4()
        case.title = "Phishing case"
        case.severity = "high"
        case.status = "open"
        case.alert_id = uuid.uuid4()

        alert = MagicMock()
        alert.id = case.alert_id
        alert.rule_description = "Phishing email"
        alert.severity = "high"
        alert.source_ip = "1.2.3.4"
        alert.user_name = "bob"
        alert.agent_name = "mail-1"

        case_result = MagicMock()
        case_result.scalar_one_or_none.return_value = case
        alert_result = MagicMock()
        alert_result.scalar_one_or_none.return_value = alert
        triage_result = MagicMock()
        triage_result.scalar_one_or_none.return_value = None
        event_result = MagicMock()
        event_result.scalars.return_value.all.return_value = []
        exec_result = MagicMock()
        exec_result.scalars.return_value.all.return_value = []

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            side_effect=[case_result, alert_result, triage_result, event_result, exec_result]
        )
        mock_run = MagicMock()
        mock_task = MagicMock()
        ctx = HandlerContext(session=mock_session, run=mock_run, task=mock_task)

        result = await handlers.evidence_pack({"case_id": str(case.id)}, ctx)

        assert result["target_type"] == "case"
        assert result["evidence_pack"]["case"]["title"] == "Phishing case"
        assert result["evidence_pack"]["alert"]["rule_description"] == "Phishing email"


class TestGatedWriteHandlers:
    @pytest.mark.asyncio
    async def test_case_create_blocked_without_approval(self):
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        added = []
        mock_session.add = lambda obj: added.append(obj)

        defn = AgentDefinition(name="approval", agent_type="test", autonomy_level="approval")
        defn.id = uuid.uuid4()
        defn_result = MagicMock()
        defn_result.scalar_one_or_none.return_value = defn
        approval_result = MagicMock()
        approval_result.scalar_one_or_none.return_value = None
        # _check_existing_approval runs first, then _load_definition
        mock_session.execute = AsyncMock(side_effect=[approval_result, defn_result])

        mock_run = MagicMock()
        mock_run.tenant_id = uuid.uuid4()
        mock_run.definition_id = defn.id
        mock_task = MagicMock()
        ctx = HandlerContext(session=mock_session, run=mock_run, task=mock_task)

        result = await handlers.case_create(
            {"title": "Test case", "alert_id": str(uuid.uuid4()), "rationale": "need case"},
            ctx,
        )

        assert result["status"] == "blocked"
        assert result["case_id"] is None
        assert not any(isinstance(a, Case) for a in added)

    @pytest.mark.asyncio
    async def test_case_create_allowed_with_full_autonomy(self):
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        added = []
        mock_session.add = lambda obj: added.append(obj)

        defn = AgentDefinition(name="full", agent_type="test", autonomy_level="full")
        defn.id = uuid.uuid4()
        none_result = MagicMock()
        none_result.scalar_one_or_none.return_value = None
        defn_result = MagicMock()
        defn_result.scalar_one_or_none.return_value = defn
        mock_session.execute = AsyncMock(side_effect=[none_result, defn_result])

        mock_run = MagicMock()
        mock_run.tenant_id = uuid.uuid4()
        mock_run.definition_id = defn.id
        mock_task = MagicMock()
        ctx = HandlerContext(session=mock_session, run=mock_run, task=mock_task)

        result = await handlers.case_create(
            {"title": "Test case", "alert_id": str(uuid.uuid4())},
            ctx,
        )

        assert result["status"] == "open"
        assert any(isinstance(a, Case) for a in added)

    @pytest.mark.asyncio
    async def test_soar_run_blocked_without_approval(self):
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        mock_session.add = MagicMock()

        defn = AgentDefinition(name="approval", agent_type="test", autonomy_level="approval")
        defn.id = uuid.uuid4()
        defn_result = MagicMock()
        defn_result.scalar_one_or_none.return_value = defn
        approval_result = MagicMock()
        approval_result.scalar_one_or_none.return_value = None
        # _check_existing_approval runs first, then _load_definition
        mock_session.execute = AsyncMock(side_effect=[approval_result, defn_result])

        mock_run = MagicMock()
        mock_run.tenant_id = uuid.uuid4()
        mock_run.definition_id = defn.id
        mock_task = MagicMock()
        ctx = HandlerContext(session=mock_session, run=mock_run, task=mock_task)

        with patch("shared.soar.engine.SOAREngine") as mock_engine_cls:
            result = await handlers.soar_run(
                {"alert": {"id": "a1", "title": "alert"}, "rationale": "execute playbook"},
                ctx,
            )

        assert result["status"] == "blocked"
        assert result["playbook_runs"] == []
        mock_engine_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_soar_run_allowed_with_existing_approval(self):
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()

        approval = ApprovalRequest(
            tenant_id=uuid.uuid4(),
            requested_by="test",
            action_type="soar_run",
            action_params={},
            target_ref="a1",
            rationale="prior",
            risk_level="medium",
            status="approved",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        approval.id = uuid.uuid4()
        approval_result = MagicMock()
        approval_result.scalar_one_or_none.return_value = approval
        mock_session.execute = AsyncMock(return_value=approval_result)

        mock_run = MagicMock()
        mock_run.tenant_id = approval.tenant_id
        mock_run.definition_id = uuid.uuid4()
        mock_task = MagicMock()
        ctx = HandlerContext(session=mock_session, run=mock_run, task=mock_task)

        with patch("shared.soar.engine.SOAREngine") as mock_engine_cls:
            engine = MagicMock()
            engine.run_for_alert = AsyncMock(return_value=[{"playbook": "p1"}])
            mock_engine_cls.return_value = engine

            result = await handlers.soar_run({"alert": {"id": "a1", "title": "alert"}}, ctx)

        assert result["playbook_runs"] == [{"playbook": "p1"}]
        engine.run_for_alert.assert_called_once()
