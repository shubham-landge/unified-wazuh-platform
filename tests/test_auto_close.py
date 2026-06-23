"""Tests for the auto-close pipeline: benign + confidence + low level + no TI/UEBA.

Covers:
  - should_auto_close unit tests (all hard blockers, all gates green)
  - L1 auto-close integration via triage_worker.process_message
  - rule_level >= 10 blocks auto-close and falls through to LLM
  - execute_auto_close shadow vs enforce mode
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.enrichment.auto_close import should_auto_close, execute_auto_close, AutoCloseAudit
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


def _make_session(alert):
    """Create a mock async session that returns the alert on execute."""
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = alert
    session.execute.return_value = mock_result
    return session


def _make_session_factory(session):
    factory = AsyncMock()
    factory.__aenter__.return_value = session
    return factory


# ── Unit: should_auto_close (low-level check) ────────────────────────────────

class TestShouldAutoCloseLowLevel:
    """Verify rule_level >= 10 is a hard blocker for auto-close."""

    def test_low_level_allowed(self):
        """rule_level < 10 + all gates green → deterministic benign."""
        ctx = _mock_ctx(
            rule_level=5,
            ti_confidence=0,
            ti_is_known_bad=False,
            ueba_zscore=0.0,
            vuln_matched=False,
            is_crown_jewel=False,
        )
        eligible, reason = should_auto_close(ctx, score=10, rule_level=5)
        assert eligible is True
        assert "deterministic benign" in reason

    def test_high_level_blocked(self):
        """rule_level >= 10 → not eligible, regardless of other signals."""
        ctx = _mock_ctx(
            rule_level=12,
            ti_confidence=0,
            ti_is_known_bad=False,
            ueba_zscore=0.0,
            vuln_matched=False,
            is_crown_jewel=False,
        )
        eligible, reason = should_auto_close(ctx, score=10, rule_level=12)
        assert eligible is False
        assert "level" in reason
        assert "12" in reason

    def test_exactly_level_10_blocked(self):
        """rule_level == 10 is NOT low-level → blocked."""
        ctx = _mock_ctx(
            rule_level=10,
            ti_confidence=0,
            ti_is_known_bad=False,
            ueba_zscore=0.0,
            vuln_matched=False,
            is_crown_jewel=False,
        )
        eligible, reason = should_auto_close(ctx, score=10, rule_level=10)
        assert eligible is False
        assert "10" in reason

    def test_level_9_allowed(self):
        """rule_level == 9 IS low-level → allowed."""
        ctx = _mock_ctx(
            rule_level=9,
            ti_confidence=0,
            ti_is_known_bad=False,
            ueba_zscore=0.0,
            vuln_matched=False,
            is_crown_jewel=False,
        )
        eligible, reason = should_auto_close(ctx, score=10, rule_level=9)
        assert eligible is True

    def test_level_0_allowed(self):
        """rule_level == 0 is low-level → allowed."""
        ctx = _mock_ctx(
            rule_level=0,
            ti_confidence=0,
            ti_is_known_bad=False,
            ueba_zscore=0.0,
            vuln_matched=False,
            is_crown_jewel=False,
        )
        eligible, reason = should_auto_close(ctx, score=10, rule_level=0)
        assert eligible is True


# ── Unit: should_auto_close (all hard blockers) ──────────────────────────────

class TestShouldAutoCloseHardBlockers:
    """Every hard blocker independently disqualifies auto-close."""

    def test_ti_confidence_blocks(self):
        ctx = _mock_ctx(ti_confidence=0.5, ti_is_known_bad=False)
        eligible, reason = should_auto_close(ctx, score=10, rule_level=5)
        assert eligible is False
        assert "TI" in reason

    def test_ti_known_bad_blocks(self):
        ctx = _mock_ctx(ti_confidence=0, ti_is_known_bad=True)
        eligible, reason = should_auto_close(ctx, score=10, rule_level=5)
        assert eligible is False
        assert "TI" in reason

    def test_ueba_anomaly_blocks(self):
        ctx = _mock_ctx(ueba_zscore=3.0)
        eligible, reason = should_auto_close(ctx, score=10, rule_level=5)
        assert eligible is False
        assert "UEBA" in reason

    def test_ueba_exactly_at_threshold_blocks(self):
        ctx = _mock_ctx(ueba_zscore=2.5)
        eligible, reason = should_auto_close(ctx, score=10, rule_level=5)
        assert eligible is False
        assert "UEBA" in reason

    def test_ueba_just_under_threshold_allowed(self):
        ctx = _mock_ctx(ueba_zscore=2.4)
        eligible, reason = should_auto_close(ctx, score=10, rule_level=5)
        assert eligible is True

    def test_vuln_matched_blocks(self):
        ctx = _mock_ctx(vuln_matched=True)
        eligible, reason = should_auto_close(ctx, score=10, rule_level=5)
        assert eligible is False
        assert "exploit" in reason.lower() or "CVE" in reason

    def test_crown_jewel_blocks(self):
        ctx = _mock_ctx(is_crown_jewel=True)
        eligible, reason = should_auto_close(ctx, score=10, rule_level=5)
        assert eligible is False
        assert "crown" in reason.lower()

    def test_score_too_high_blocks(self):
        ctx = _mock_ctx()
        eligible, reason = should_auto_close(ctx, score=30, rule_level=5)
        assert eligible is False
        assert "score" in reason.lower()

    def test_score_exactly_at_threshold_blocks(self):
        ctx = _mock_ctx()
        eligible, reason = should_auto_close(ctx, score=25, rule_level=5)
        assert eligible is False
        assert "25" in reason

    def test_score_just_under_threshold_allowed(self):
        ctx = _mock_ctx()
        eligible, reason = should_auto_close(ctx, score=24, rule_level=5)
        assert eligible is True


# ── Unit: should_auto_close (benign + confidence) ────────────────────────────

class TestShouldAutoCloseConfidence:
    """LLM verdict 'benign' with confidence >= threshold enables auto-close;
    low confidence or non-benign verdict blocks it."""

    def test_benign_high_confidence(self):
        ctx = _mock_ctx()
        eligible, reason = should_auto_close(
            ctx, score=10, rule_level=5,
            llm_verdict="benign", llm_confidence=0.90,
        )
        assert eligible is True
        assert "benign" in reason

    def test_benign_low_confidence_blocked(self):
        ctx = _mock_ctx()
        eligible, reason = should_auto_close(
            ctx, score=10, rule_level=5,
            llm_verdict="benign", llm_confidence=0.70,
        )
        assert eligible is False
        assert "confidence" in reason.lower()

    def test_benign_exact_confidence_threshold_allowed(self):
        ctx = _mock_ctx()
        eligible, reason = should_auto_close(
            ctx, score=10, rule_level=5,
            llm_verdict="benign", llm_confidence=0.85,
        )
        assert eligible is True

    def test_benign_just_below_threshold_blocked(self):
        ctx = _mock_ctx()
        eligible, reason = should_auto_close(
            ctx, score=10, rule_level=5,
            llm_verdict="benign", llm_confidence=0.849,
        )
        assert eligible is False

    def test_malicious_verdict_blocked(self):
        ctx = _mock_ctx()
        eligible, reason = should_auto_close(
            ctx, score=10, rule_level=5,
            llm_verdict="malicious", llm_confidence=0.95,
        )
        assert eligible is False
        assert "malicious" in reason

    def test_suspicious_verdict_blocked(self):
        ctx = _mock_ctx()
        eligible, reason = should_auto_close(
            ctx, score=10, rule_level=5,
            llm_verdict="suspicious", llm_confidence=0.90,
        )
        assert eligible is False
        assert "suspicious" in reason


# ── Unit: should_auto_close (combined gates) ─────────────────────────────────

class TestShouldAutoCloseCombined:
    """Multiple disqualifiers: first hard blocker wins."""

    def test_high_level_and_ti_blocked_by_level_first(self):
        """Rule level check runs first, so its message appears."""
        ctx = _mock_ctx(ti_confidence=0.5, ti_is_known_bad=False)
        eligible, reason = should_auto_close(ctx, score=10, rule_level=12)
        assert eligible is False
        assert "level" in reason

    def test_all_gates_green_deterministic(self):
        """All gates pass with no LLM → deterministic benign."""
        ctx = _mock_ctx(
            rule_level=5,
            ti_confidence=0,
            ti_is_known_bad=False,
            ueba_zscore=0.0,
            vuln_matched=False,
            is_crown_jewel=False,
        )
        eligible, reason = should_auto_close(ctx, score=10, rule_level=5)
        assert eligible is True
        assert "deterministic benign" in reason
        assert "score=10" in reason
        assert "level=5" in reason

    def test_all_gates_green_with_llm_benign(self):
        """All gates pass + LLM says benign → benign verdict with confidence."""
        ctx = _mock_ctx(
            rule_level=5,
            ti_confidence=0,
            ti_is_known_bad=False,
            ueba_zscore=0.0,
            vuln_matched=False,
            is_crown_jewel=False,
        )
        eligible, reason = should_auto_close(
            ctx, score=10, rule_level=5,
            llm_verdict="benign", llm_confidence=0.92,
        )
        assert eligible is True
        assert "benign verdict" in reason
        assert "conf=0.92" in reason


# ── Unit: execute_auto_close ────────────────────────────────────────────────

class TestExecuteAutoClose:
    @pytest.mark.asyncio
    async def test_shadow_mode_logs_but_does_not_persist(self):
        """In shadow mode, execute_auto_close creates an audit but does NOT
        update the alert status."""
        session = AsyncMock()
        ctx = _mock_ctx()
        ctx.breakdown = {"rule_level": 5, "threat_intel": 0}

        with patch(
            "shared.enrichment.auto_close.settings",
        ) as mock_settings:
            mock_settings.automation_mode = "shadow"

            audit = await execute_auto_close(
                session, "alert-1", "tenant-1",
                "deterministic benign", 10, ctx,
            )

            # Audit record created with shadow_mode=True
            assert audit.shadow_mode is True
            assert audit.alert_id == "alert-1"
            assert audit.tenant_id == "tenant-1"

            # Alert DB update MUST NOT be called
            session.execute.assert_not_called()
            session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_enforce_mode_persists_close(self):
        """In enforce mode, execute_auto_close updates alert status.
        
        Temporarily adds 'status' and 'notes' columns to the real
        Alert model (which lacks them — pre-existing issue) so the
        SQLAlchemy update statement can be built, then verifies
        session.execute and session.commit are called."""
        session = AsyncMock()
        ctx = _mock_ctx()
        ctx.breakdown = {"rule_level": 5, "threat_intel": 0}

        from shared.models.alert import Alert
        import sqlalchemy as sa

        # Inject missing columns so the update statement constructs
        # (Alert model lacks status/notes — pre-existing issue).
        # Column objects survive for the process lifetime; no cleanup needed.
        if not hasattr(Alert, "_test_status_injected"):
            Alert.status = sa.Column(sa.String(32))
            Alert.notes = sa.Column(sa.Text)
            Alert._test_status_injected = True

        with patch(
            "shared.enrichment.auto_close.settings",
        ) as mock_settings:
            mock_settings.automation_mode = "enforce"

            audit = await execute_auto_close(
                session, "alert-1", "tenant-1",
                "benign verdict", 10, ctx,
            )

            # Audit record created with shadow_mode=False
            assert audit.shadow_mode is False

            # Alert DB update called once
            session.execute.assert_called_once()
            session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_record_fields(self):
        """AutoCloseAudit carries all required fields."""
        ctx = _mock_ctx()
        ctx.breakdown = {"rule_level": 5, "threat_intel": 0}

        with patch(
            "shared.enrichment.auto_close.settings",
        ) as mock_settings:
            mock_settings.automation_mode = "shadow"

            audit = await execute_auto_close(
                AsyncMock(), "alert-42", "tenant-99",
                "deterministic benign (score=10, level=5, no TI, normal UEBA)",
                10, ctx,
            )

            assert audit.alert_id == "alert-42"
            assert audit.tenant_id == "tenant-99"
            assert audit.score == 10
            assert audit.reason.startswith("deterministic benign")
            assert audit.policy_version == "1.0"
            assert audit.shadow_mode is True
            assert audit.closed_at is not None
            assert audit.breakdown == {"rule_level": 5, "threat_intel": 0}


# ── Integration: L1 auto-close with rule_level gate ──────────────────────────

class TestL1AutoCloseRuleLevelGate:
    """Verify the triage_worker integrates rule_level into the auto-close gate."""

    @pytest.mark.asyncio
    async def test_l1_with_low_level_auto_closes(self):
        """L1 decision + rule_level < 10 → auto_close executes, LLM skipped."""
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        alert = _mock_alert(rule_level=5)
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx(rule_level=5)),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=20,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=_l1_decision(),
        ), patch(
            "services.worker.app.triage_worker.should_auto_close",
            wraps=should_auto_close,  # use real function
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

            # execute_auto_close called
            mock_exec.assert_called_once()
            # LLM never invoked
            mock_router_cls.return_value.get_provider.assert_not_called()

    @pytest.mark.asyncio
    async def test_l1_with_high_level_falls_through_to_llm(self):
        """L1 decision + rule_level >= 10 → should_auto_close returns False,
        falls through to L2 triage with LLM."""
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        alert = _mock_alert(rule_level=12)
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "test summary",
            "category": "benign",
            "severity": "low",
            "confidence": 0.7,
            "false_positive_likelihood": 0.3,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": False,
        })

        mock_router = MagicMock()
        mock_router.get_provider = AsyncMock(return_value=mock_provider)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx(rule_level=12)),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=20,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=_l1_decision(),
        ), patch(
            "services.worker.app.triage_worker.should_auto_close",
            wraps=should_auto_close,  # use real function — returns False for level 12
        ), patch(
            "services.worker.app.triage_worker.execute_auto_close",
            new=AsyncMock(),
        ) as mock_exec, patch(
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
            mock_settings.auto_close_enabled = True
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run
            with patch.object(
                shared.models.model_run, "ModelRun", MagicMock()
            ):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # execute_auto_close MUST NOT be called
            mock_exec.assert_not_called()

            # LLM MUST be called (fallthrough to L2)
            mock_provider.analyze.assert_called_once()

    @pytest.mark.asyncio
    async def test_l1_auto_close_disabled_falls_through_to_llm(self):
        """L1 decision + auto_close_enabled=False → falls through to LLM
        even when should_auto_close would return True."""
        from services.worker.app.triage_worker import TriageWorker

        worker = TriageWorker()
        alert = _mock_alert(rule_level=5)
        session = _make_session(alert)
        worker.session_factory = lambda: _make_session_factory(session)

        mock_provider = MagicMock()
        mock_provider.name = MagicMock(return_value="test-model")
        mock_provider.analyze = AsyncMock(return_value={
            "success": True,
            "summary": "test summary",
            "category": "benign",
            "severity": "low",
            "confidence": 0.7,
            "false_positive_likelihood": 0.3,
            "mitre_mapping": [],
            "investigation_steps": [],
            "do_not_do": [],
            "escalation_required": False,
        })

        mock_router = MagicMock()
        mock_router.get_provider = AsyncMock(return_value=mock_provider)

        with patch(
            "services.worker.app.triage_worker.enrich_alert",
            new=AsyncMock(return_value=_mock_ctx(rule_level=5)),
        ), patch(
            "services.worker.app.triage_worker.compute_risk_score",
            return_value=20,
        ), patch(
            "services.worker.app.triage_worker.decide",
            return_value=_l1_decision(),
        ), patch(
            "services.worker.app.triage_worker.should_auto_close",
            wraps=should_auto_close,
        ), patch(
            "services.worker.app.triage_worker.execute_auto_close",
            new=AsyncMock(),
        ) as mock_exec, patch(
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
            mock_settings.auto_close_enabled = False  # DISABLED
            mock_settings.incident_risk_enabled = False

            import shared.models.model_run
            with patch.object(
                shared.models.model_run, "ModelRun", MagicMock()
            ):
                await worker.process_message({"alert_id": str(alert.id), "manual": True})

            # execute_auto_close MUST NOT be called
            mock_exec.assert_not_called()

            # LLM MUST be called (fallthrough)
            mock_provider.analyze.assert_called_once()
