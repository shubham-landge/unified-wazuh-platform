"""Tests for the decision gate routing wired into triage_worker.process_message.

Verifies L0 suppress, L1 auto-close, and L3/L4 deterministic escalation
branches correctly gate the LLM invocation flow.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.enrichment.decision import Decision, DecisionLevel
from shared.enrichment.risk_score import EnrichmentContext


def _mock_alert(alert_id=None, rule_level=10, rule_id=1001, tenant_id=None):
    tid = tenant_id or uuid.uuid4()
    return SimpleNamespace(
        id=alert_id or uuid.uuid4(),
        rule_level=rule_level,
        rule_id=rule_id,
        rule_groups=[],
        rule_description="Test alert",
        agent_name="test-agent",
        agent_ip="10.0.0.1",
        source_ip="192.168.1.1",
        user_name="testuser",
        process_name="testproc",
        mitre_tactic="Execution",
        mitre_technique="T1059",
        tenant_id=tid,
        status="open",
    )


def _mock_ctx(**kwargs) -> EnrichmentContext:
    return EnrichmentContext(rule_level=kwargs.pop("rule_level", 10), **kwargs)


def _l0_decision():
    return Decision(
        level=DecisionLevel.L0_SUPPRESS,
        score=5,
        reason="test L0 suppress",
        skip_llm=True,
        fast_llm_only=False,
        auto_verdict="benign",
    )


def _l1_decision():
    return Decision(
        level=DecisionLevel.L1_AUTO_CLOSE,
        score=20,
        reason="test L1 auto-close",
        skip_llm=True,
        fast_llm_only=False,
        auto_verdict="benign",
        auto_severity="low",
    )


def _l3_decision():
    return Decision(
        level=DecisionLevel.L3_ESCALATE,
        score=70,
        reason="test L3 escalate",
        skip_llm=False,
        fast_llm_only=True,
        auto_verdict="malicious",
        auto_severity="high",
    )


def _make_session(alert):
    """Create a mock async session that returns the alert on execute."""
    session = AsyncMock()
    # session.execute(select(Alert).where(...)) → .scalar_one_or_none() → alert
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = alert
    session.execute.return_value = mock_result
    return session


def _make_session_factory(session):
    factory = AsyncMock()
    factory.__aenter__.return_value = session
    return factory


# ── L0 Suppress ─────────────────────────────────────────────────────────────

class TestL0Suppress:
    @pytest.mark.asyncio
    async def test_l0_suppress_skips_llm(self):
        """L0 decision → alert marked suppressed, no LLM invocation, returns early."""
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx()),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=5,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=_l0_decision(),
        ), patch(
            "services.worker.app.triage_worker.TieredRouter",
        ) as mock_router_cls, patch(
            "services.worker.app.triage_worker.triage_cache",
        ) as mock_cache, patch(
            "services.worker.app.triage_worker.settings",
        ) as mock_settings:
            mock_settings.automation_mode = "enforce"
            # Use manual=True to skip noise_reduction path
            await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # Alert should be marked suppressed
            assert alert.status == "suppressed"
            session.commit.assert_called()

            # LLM provider MUST NOT be called
            mock_router_cls.return_value.get_provider.assert_not_called()
            mock_cache.lookup.assert_not_called()


# ── L1 Auto-Close ────────────────────────────────────────────────────────────

class TestL1AutoClose:
    @pytest.mark.asyncio
    async def test_l1_auto_close_calls_auto_close(self):
        """L1 decision → auto_close functions called, no LLM invocation."""
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx()),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=20,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=_l1_decision(),
        ), patch(
            "services.worker.app.triage_worker.should_auto_close",
            return_value=(True, "deterministic benign"),
        ), patch(
            "services.worker.app.triage_worker.execute_auto_close",
            new=AsyncMock(),
        ) as mock_exec, patch(
            "services.worker.app.triage_worker.TieredRouter",
        ) as mock_router_cls, patch(
            "services.worker.app.triage_worker.settings",
        ) as mock_settings:
            mock_settings.auto_close_enabled = True

            await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # execute_auto_close should be called
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args
            assert call_args[0][1] == str(alert.id)

            # LLM provider MUST NOT be called
            mock_router_cls.return_value.get_provider.assert_not_called()


# ── L3 Escalate ─────────────────────────────────────────────────────────────

class TestL3Escalate:
    @pytest.mark.asyncio
    async def test_l3_escalate_uses_fast_tier(self):
        """L3 decision → fast tier LLM used, force_fast=True passed to router."""
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "test summary",
            "category": "benign",
            "severity": "low",
            "confidence": 0.3,
            "false_positive_likelihood": 0.8,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": False,
        })

        mock_router = MagicMock()
        mock_router.get_provider = AsyncMock(return_value=mock_provider)

        # Capture the AiTriageResult fields to verify override
        captured_fields = {}

        class MockTriageResult:
            def __init__(self, **fields):
                captured_fields.update(fields)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx()),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=70,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=_l3_decision(),
        ), patch(
            "services.worker.app.triage_worker.TieredRouter",
            return_value=mock_router,
        ), patch(
            "services.worker.app.triage_worker.triage_cache",
        ) as mock_cache, patch(
            "services.worker.app.triage_worker.triage_rag",
        ) as mock_rag, patch(
            "services.worker.app.triage_worker.settings",
        ) as mock_settings, patch(
            "services.worker.app.triage_worker.AiTriageResult",
            new=MockTriageResult,
        ), patch(
            "shared.models.model_run.ModelRun",
        ), patch(
            "services.worker.app.triage_worker.Case",
        ), patch(
            "services.worker.app.triage_worker.CaseEvent",
        ), patch(
            "services.worker.app.triage_worker.CaseInvestigationStep",
        ):
            mock_cache.lookup = AsyncMock(return_value=None)
            mock_rag.build_triage_context = AsyncMock(return_value="")
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run  # ensure imported
            with patch.object(
                shared.models.model_run, "ModelRun", MagicMock()
            ):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # Verify fast tier was forced
            call_kwargs = mock_router.get_provider.call_args.kwargs
            assert call_kwargs["force_fast"] is True, (
                f"Expected force_fast=True for L3, got {call_kwargs}"
            )

            # LLM should be called (for narrative)
            mock_provider.analyze.assert_called_once()

            # Verify deterministic overrides in persisted fields
            assert captured_fields.get("severity") == "high", (
                f"Expected severity='high' for L3, got {captured_fields.get('severity')}"
            )
            assert captured_fields.get("category") == "malicious", (
                f"Expected category='malicious' for L3, got {captured_fields.get('category')}"
            )
            assert captured_fields.get("escalation_required") is True, (
                f"Expected escalation_required=True, got {captured_fields.get('escalation_required')}"
            )

    @pytest.mark.asyncio
    async def test_l3_escalate_with_cache_hit_still_overrides(self):
        """L3 with cache hit should still apply deterministic override to
        cached result_data."""
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name.return_value = "ollama-fast"
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "Old narrative",
            "category": "benign",
            "severity": "low",
            "confidence": 0.5,
            "false_positive_likelihood": 0.8,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": False,
        })

        mock_router = MagicMock()
        mock_router.get_provider = AsyncMock(return_value=mock_provider)

        # Cache returns a stale verdict — must be overridden for L3
        cached_data = {
            "summary": "Old narrative",
            "category": "benign",
            "severity": "low",
            "confidence": 0.5,
            "false_positive_likelihood": 0.8,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": False,
        }

        captured_fields = {}

        class MockTriageResult:
            def __init__(self, **fields):
                captured_fields.update(fields)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx()),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=70,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=_l3_decision(),
        ), patch(
            "services.worker.app.triage_worker.TieredRouter",
            return_value=mock_router,
        ), patch(
            "services.worker.app.triage_worker.triage_cache",
        ) as mock_cache, patch(
            "services.worker.app.triage_worker.settings",
        ) as mock_settings, patch(
            "services.worker.app.triage_worker.AiTriageResult",
            new=MockTriageResult,
        ), patch(
            "shared.models.model_run.ModelRun",
        ), patch(
            "services.worker.app.triage_worker.Case",
        ), patch(
            "services.worker.app.triage_worker.CaseEvent",
        ), patch(
            "services.worker.app.triage_worker.CaseInvestigationStep",
        ), patch(
            "services.worker.app.triage_worker.triage_rag",
        ) as mock_rag, patch(
            "services.worker.app.triage_worker.json",
        ):
            mock_cache.lookup = AsyncMock(return_value=dict(cached_data))
            mock_rag.build_triage_context = AsyncMock(return_value="")
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run
            with patch.object(
                shared.models.model_run, "ModelRun", MagicMock()
            ):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # L3 does not consult cache — LLM is called; deterministic override still applies
            mock_provider.analyze.assert_called()

            # Cached verdict should be overridden for L3
            assert captured_fields.get("severity") == "high", (
                f"Cache hit + L3 should override severity, got {captured_fields.get('severity')}"
            )
            assert captured_fields.get("category") == "malicious"
            assert captured_fields.get("escalation_required") is True
