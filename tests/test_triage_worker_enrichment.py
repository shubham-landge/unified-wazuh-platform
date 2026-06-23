"""Tests for triage_worker enrichment integration with shadow-mode support.

Verifies the enrichment pipeline (enrich_alert → compute_risk_score → decide)
is wired between the noise gate and LLM, and that shadow mode
(AUTOMATION_MODE=shadow) suppresses destructive actions while still
running enrichment and the LLM for observability.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.worker.app.triage_worker import TriageWorker
from shared.enrichment.decision import Decision, DecisionLevel
from shared.enrichment.risk_score import EnrichmentContext


# ── Helpers ──────────────────────────────────────────────────────────────────

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


def _l4_decision():
    return Decision(
        level=DecisionLevel.L4_CRITICAL,
        score=92,
        reason="test L4 critical",
        skip_llm=False,
        fast_llm_only=True,
        auto_verdict="malicious",
        auto_severity="critical",
    )


def _make_session(alert):
    """Create a mock async session that returns the alert on execute."""
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = alert
    # Allow execute().scalar_one_or_none() pattern for Case lookups as well
    session.execute.return_value = mock_result
    return session


def _make_session_factory(session):
    factory = AsyncMock()
    factory.__aenter__.return_value = session
    return factory


# ── TriageWorker._is_shadow_mode ─────────────────────────────────────────────

class TestIsShadowMode:
    def test_is_shadow_mode_true_by_default(self):
        """settings.automation_mode defaults to 'shadow'."""
        worker = TriageWorker()
        with patch.object(worker, "_is_shadow_mode", wraps=worker._is_shadow_mode):
            assert worker._is_shadow_mode() is True

    def test_is_shadow_mode_false_when_enforce(self):
        """When settings.automation_mode='enforce', _is_shadow_mode returns False."""
        worker = TriageWorker()
        with patch(
            "services.worker.app.triage_worker.settings",
        ) as mock_settings:
            mock_settings.automation_mode = "enforce"
            assert worker._is_shadow_mode() is False

    def test_is_shadow_mode_case_insensitive(self):
        """SHADOW / Shadow should also count as shadow mode."""
        worker = TriageWorker()
        with patch(
            "services.worker.app.triage_worker.settings",
        ) as mock_settings:
            mock_settings.automation_mode = "SHADOW"
            assert worker._is_shadow_mode() is True
            mock_settings.automation_mode = "Shadow"
            assert worker._is_shadow_mode() is True


# ── Shadow mode: L0 Suppress ─────────────────────────────────────────────────

class TestL0ShadowMode:
    @pytest.mark.asyncio
    async def test_shadow_mode_l0_does_not_change_status(self):
        """In shadow mode, L0 suppress logs but does NOT set alert.status='suppressed'."""
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
            "services.worker.app.triage_worker.settings",
        ) as mock_settings:
            mock_settings.automation_mode = "shadow"

            await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # Alert status MUST NOT be changed
            assert alert.status == "open", (
                f"Shadow mode should not change alert status, got {alert.status}"
            )
            # LLM MUST NOT be called
            mock_router_cls.return_value.get_provider.assert_not_called()

    @pytest.mark.asyncio
    async def test_enforce_mode_l0_sets_status_suppressed(self):
        """In enforce mode, L0 suppress sets alert.status='suppressed'."""
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
            "services.worker.app.triage_worker.settings",
        ) as mock_settings:
            mock_settings.automation_mode = "enforce"

            await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # Alert status MUST be changed
            assert alert.status == "suppressed", (
                f"Enforce mode should suppress alert, got {alert.status}"
            )
            mock_router_cls.return_value.get_provider.assert_not_called()


# ── Shadow mode: L1 Auto-Close ───────────────────────────────────────────────

class TestL1ShadowMode:
    @pytest.mark.asyncio
    async def test_shadow_mode_l1_calls_execute_auto_close(self):
        """In shadow mode, L1 auto-close still calls execute_auto_close
        (which internally handles shadow vs enforce)."""
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
            mock_settings.automation_mode = "shadow"
            mock_settings.auto_close_enabled = True

            await worker.process_message({"alert_id": str(alert.id), "manual": True})

            mock_exec.assert_called_once()
            # LLM should not be called
            mock_router_cls.return_value.get_provider.assert_not_called()

    @pytest.mark.asyncio
    async def test_enforce_mode_l1_calls_execute_auto_close(self):
        """In enforce mode, L1 auto-close calls execute_auto_close (which
        actually persists the close)."""
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
            mock_settings.automation_mode = "enforce"
            mock_settings.auto_close_enabled = True

            await worker.process_message({"alert_id": str(alert.id), "manual": True})

            mock_exec.assert_called_once()
            mock_router_cls.return_value.get_provider.assert_not_called()


# ── Shadow mode: L3 Escalate ─────────────────────────────────────────────────

class TestL3ShadowMode:
    @pytest.mark.asyncio
    async def test_shadow_mode_l3_does_not_override_verdict(self):
        """In shadow mode, L3 runs the LLM but does NOT apply the deterministic
        override — the LLM's own verdict is preserved."""
        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "LLM narrative",
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
            mock_settings.automation_mode = "shadow"
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run
            with patch.object(shared.models.model_run, "ModelRun", MagicMock()):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # LLM should still be called (for narrative/observability)
            mock_provider.analyze.assert_called_once()

            # Verify LLM's verdict is NOT overridden
            assert captured_fields.get("severity") == "low", (
                f"Shadow mode should preserve LLM severity='low', "
                f"got {captured_fields.get('severity')}"
            )
            assert captured_fields.get("category") == "benign", (
                f"Shadow mode should preserve LLM category='benign', "
                f"got {captured_fields.get('category')}"
            )
            assert captured_fields.get("escalation_required") is False, (
                f"Shadow mode should preserve LLM escalation_required=False, "
                f"got {captured_fields.get('escalation_required')}"
            )

    @pytest.mark.asyncio
    async def test_enforce_mode_l3_applies_deterministic_override(self):
        """In enforce mode, L3 applies the deterministic override over the
        LLM's verdict."""
        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "LLM narrative",
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
            mock_settings.automation_mode = "enforce"
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run
            with patch.object(shared.models.model_run, "ModelRun", MagicMock()):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # Verify deterministic overrides applied
            assert captured_fields.get("severity") == "high", (
                f"Enforce mode L3 should set severity='high', "
                f"got {captured_fields.get('severity')}"
            )
            assert captured_fields.get("category") == "malicious"
            assert captured_fields.get("escalation_required") is True


# ── Shadow mode: L4 Critical ─────────────────────────────────────────────────

class TestL4ShadowMode:
    @pytest.mark.asyncio
    async def test_shadow_mode_l4_does_not_override_verdict(self):
        """In shadow mode, L4 runs LLM but does NOT override verdict."""
        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "LLM narrative",
            "category": "suspicious",
            "severity": "medium",
            "confidence": 0.6,
            "false_positive_likelihood": 0.5,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": True,
        })

        mock_router = MagicMock()
        mock_router.get_provider = AsyncMock(return_value=mock_provider)

        captured_fields = {}

        class MockTriageResult:
            def __init__(self, **fields):
                captured_fields.update(fields)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx()),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=92,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=_l4_decision(),
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
            mock_settings.automation_mode = "shadow"
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run
            with patch.object(shared.models.model_run, "ModelRun", MagicMock()):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # LLM should still be called for observability
            mock_provider.analyze.assert_called_once()

            # LLM's own verdict preserved (not overridden to critical/malicious)
            assert captured_fields.get("severity") == "medium", (
                f"Shadow mode L4 should preserve LLM severity='medium', "
                f"got {captured_fields.get('severity')}"
            )
            assert captured_fields.get("category") == "suspicious"

    @pytest.mark.asyncio
    async def test_enforce_mode_l4_applies_deterministic_override(self):
        """In enforce mode, L4 applies critical override."""
        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "LLM narrative",
            "category": "suspicious",
            "severity": "medium",
            "confidence": 0.6,
            "false_positive_likelihood": 0.5,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": True,
        })

        mock_router = MagicMock()
        mock_router.get_provider = AsyncMock(return_value=mock_provider)

        captured_fields = {}

        class MockTriageResult:
            def __init__(self, **fields):
                captured_fields.update(fields)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx()),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=92,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=_l4_decision(),
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
            mock_settings.automation_mode = "enforce"
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run
            with patch.object(shared.models.model_run, "ModelRun", MagicMock()):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            assert captured_fields.get("severity") == "critical"
            assert captured_fields.get("category") == "malicious"
            assert captured_fields.get("escalation_required") is True


# ── Shadow mode: Force-fast tier for L3/L4 ───────────────────────────────────

class TestL3L4ForceFast:
    @pytest.mark.asyncio
    async def test_shadow_mode_l3_still_uses_fast_tier(self):
        """Even in shadow mode, L3 routes to fast tier for LLM narrative."""
        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="ollama-fast")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "narrative",
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
            mock_settings.automation_mode = "shadow"
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run
            with patch.object(shared.models.model_run, "ModelRun", MagicMock()):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            call_kwargs = mock_router.get_provider.call_args.kwargs
            assert call_kwargs["force_fast"] is True, (
                f"Shadow mode L3 should still use fast tier, got force_fast={call_kwargs.get('force_fast')}"
            )


# ── Shadow mode: Enrichment pipeline wiring ──────────────────────────────────

class TestEnrichmentPipelineWiring:
    """Verify enrich→score→decide runs between noise gate and LLM."""

    @pytest.mark.asyncio
    async def test_enrichment_runs_before_llm(self):
        """enrich_alert, compute_risk_score, and decide are all called
        BEFORE the LLM provider."""
        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "test",
            "category": "benign",
            "severity": "low",
            "confidence": 0.5,
            "false_positive_likelihood": 0.5,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": False,
        })

        mock_router = MagicMock()
        mock_router.get_provider = AsyncMock(return_value=mock_provider)

        call_order = []

        async def _tracked_enrich(*args, **kwargs):
            call_order.append("enrich")
            return _mock_ctx()

        def _tracked_score(*args, **kwargs):
            call_order.append("score")
            return 45

        def _tracked_decide(*args, **kwargs):
            call_order.append("decide")
            return Decision(
                level=DecisionLevel.L2_TRIAGE,
                score=45,
                reason="test L2",
                skip_llm=False,
                fast_llm_only=False,
            )

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=_tracked_enrich,
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            new=_tracked_score,
        ), patch(
            "services.worker.app.triage_worker.decide",
            new=_tracked_decide,
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

            import shared.models.model_run
            with patch.object(shared.models.model_run, "ModelRun", MagicMock()):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # Check call order
            assert call_order.index("enrich") < call_order.index("score"), (
                "enrich must run before score"
            )
            assert call_order.index("score") < call_order.index("decide"), (
                "score must run before decide"
            )
            # LLM called after decision
            mock_provider.analyze.assert_called_once()

    @pytest.mark.asyncio
    async def test_enrichment_context_passed_to_llm_prompt(self):
        """Enrichment context (TI, UEBA, GeoIP, vulns) is injected into the
        LLM user prompt."""
        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        ctx = _mock_ctx(
            ti_confidence=0.9,
            ti_is_known_bad=True,
            ueba_zscore=3.8,
            geo_tor_vpn=True,
            vuln_matched=True,
            vuln_epss=0.75,
            vuln_is_kev=True,
        )

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "test",
            "category": "benign",
            "severity": "low",
            "confidence": 0.5,
            "false_positive_likelihood": 0.5,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": False,
        })

        mock_router = MagicMock()
        mock_router.get_provider = AsyncMock(return_value=mock_provider)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=ctx),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=65,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=Decision(
                level=DecisionLevel.L2_TRIAGE,
                score=65,
                reason="test",
                skip_llm=False,
                fast_llm_only=False,
            ),
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

            import shared.models.model_run
            with patch.object(shared.models.model_run, "ModelRun", MagicMock()):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # Check that the user_prompt passed to analyze() contains enrichment data
            call_args = mock_provider.analyze.call_args
            user_prompt = call_args.kwargs.get("user_prompt", "")
            assert "TI" in user_prompt or "Threat Intel" in user_prompt or "known bad" in user_prompt, (
                f"User prompt should contain TI enrichment, got: {user_prompt[:500]}"
            )
            assert "UEBA" in user_prompt or "z-score" in user_prompt, (
                f"User prompt should contain UEBA enrichment"
            )
            assert "GeoIP" in user_prompt or "Tor/VPN" in user_prompt, (
                f"User prompt should contain GeoIP enrichment"
            )
            assert "Vulnerabilities" in user_prompt or "EPSS" in user_prompt, (
                f"User prompt should contain vuln enrichment"
            )


# ── Shadow mode: Manual "Analyze" path skips the gate (no regression) ────────

class TestManualPathSkipsGate:
    @pytest.mark.asyncio
    async def test_manual_path_bypasses_decision_gate(self):
        """Manual triage with force_fast should skip the L0/L1 gate entirely
        regardless of automation_mode."""
        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "test manual",
            "category": "benign",
            "severity": "low",
            "confidence": 0.5,
            "false_positive_likelihood": 0.5,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": False,
        })

        mock_router = MagicMock()
        mock_router.get_provider = AsyncMock(return_value=mock_provider)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx()),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=5,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=_l0_decision(),  # L0 suppress — should be ignored
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
            mock_settings.automation_mode = "shadow"
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run
            with patch.object(shared.models.model_run, "ModelRun", MagicMock()):
                await worker.process_message({
                    "alert_id": str(alert.id),
                    "manual": True,
                    "force_fast": True,
                })

            # Manual path must still call LLM even if decision says L0 suppress
            mock_provider.analyze.assert_called_once()
            # Alert status should NOT be changed
            assert alert.status == "open"


# ── Shadow mode: Full integration with non-manual path (noise gate + enrichment) ──

class TestNonManualFlow:
    @pytest.mark.asyncio
    async def test_non_manual_enrichment_shadow_mode(self):
        """Non-manual path runs noise gate → enrichment → decision → LLM in
        shadow mode, with no destructive actions."""
        worker = TriageWorker()
        alert = _mock_alert()
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "test",
            "category": "benign",
            "severity": "low",
            "confidence": 0.5,
            "false_positive_likelihood": 0.5,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": False,
        })

        mock_router = MagicMock()
        mock_router.get_provider = AsyncMock(return_value=mock_provider)

        # Mock noise_reduction to allow triage
        mock_noise_decision = MagicMock()
        mock_noise_decision.should_triage = True
        mock_noise_decision.incident = None
        mock_noise_decision.action = None
        mock_noise_decision.force_fast_tier = False

        with patch(
            "services.worker.app.triage_worker.noise_reduction.evaluate",
            new=AsyncMock(return_value=mock_noise_decision),
        ), patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx()),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=45,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=Decision(
                level=DecisionLevel.L2_TRIAGE,
                score=45,
                reason="test L2",
                skip_llm=False,
                fast_llm_only=False,
            ),
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
            mock_settings.automation_mode = "shadow"
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run
            with patch.object(shared.models.model_run, "ModelRun", MagicMock()):
                await worker.process_message({"alert_id": str(alert.id)})

            # LLM should be called
            mock_provider.analyze.assert_called_once()
            # Alert status should not change
            assert alert.status == "open"
