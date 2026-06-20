"""Tests for the shared enrichment package (risk_score, decision gate, auto_close,
TI enricher, asset enricher, user enricher, UEBA history, and full pipeline).

Pure unit tests for deterministic logic; async DB-dependant enrichers use mocked sessions.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from shared.enrichment.risk_score import EnrichmentContext, compute
from shared.enrichment.decision import decide, DecisionLevel
from shared.enrichment.auto_close import should_auto_close


# ─── risk_score.compute() ───────────────────────────────────────────────────

class TestRiskScore:
    def test_zero_score_for_low_level(self):
        ctx = EnrichmentContext(rule_level=3)
        score = compute(ctx)
        assert score == 0

    def test_allowlisted_forces_zero(self):
        ctx = EnrichmentContext(rule_level=15, ti_is_known_bad=True, is_allowlisted=True)
        score = compute(ctx)
        assert score == 0
        assert ctx.breakdown.get("allowlisted") is True

    def test_level_14_gets_40_pts(self):
        ctx = EnrichmentContext(rule_level=14)
        score = compute(ctx)
        assert score == 40

    def test_level_12_gets_30_pts(self):
        ctx = EnrichmentContext(rule_level=12)
        score = compute(ctx)
        assert score == 30

    def test_ti_known_bad_adds_40(self):
        ctx = EnrichmentContext(rule_level=7, ti_is_known_bad=True)
        score = compute(ctx)
        assert score == 10 + 40  # rule_level_medium + ti_known_bad

    def test_vuln_kev_adds_35(self):
        ctx = EnrichmentContext(rule_level=7, vuln_matched=True, vuln_is_kev=True)
        score = compute(ctx)
        assert score == 10 + 35

    def test_vuln_high_epss_adds_35(self):
        ctx = EnrichmentContext(rule_level=7, vuln_matched=True, vuln_epss=0.7)
        score = compute(ctx)
        assert score == 10 + 35

    def test_ueba_critical_zscore_adds_20(self):
        ctx = EnrichmentContext(rule_level=7, ueba_zscore=6.0)
        score = compute(ctx)
        assert score == 10 + 20  # medium_level + ueba_critical

    def test_impossible_travel_adds_15(self):
        ctx = EnrichmentContext(rule_level=7, geo_impossible_travel=True)
        score = compute(ctx)
        assert score == 10 + 15

    def test_crown_jewel_applies_multiplier(self):
        ctx = EnrichmentContext(rule_level=10, is_crown_jewel=True)
        score_no_cj = compute(EnrichmentContext(rule_level=10))
        score_cj = compute(ctx)
        assert score_cj > score_no_cj
        assert score_cj == round(score_no_cj * 1.3)

    def test_confirmed_fp_reduces_score(self):
        ctx = EnrichmentContext(rule_level=10, is_confirmed_fp=True)
        score = compute(ctx)
        # 20 (rule) - 20 (fp penalty) = 0 (floor)
        assert score == 0

    def test_score_capped_at_100(self):
        ctx = EnrichmentContext(
            rule_level=15,
            ti_is_known_bad=True,
            asset_criticality=10,
            vuln_matched=True,
            vuln_is_kev=True,
            ueba_zscore=10.0,
            geo_impossible_travel=True,
            is_crown_jewel=True,
            mitre_high_impact=True,
        )
        score = compute(ctx)
        assert score == 100

    def test_breakdown_populated(self):
        ctx = EnrichmentContext(rule_level=10, ti_confidence=0.8)
        compute(ctx)
        assert "rule_level" in ctx.breakdown
        assert "threat_intel" in ctx.breakdown


# ─── decision.decide() ──────────────────────────────────────────────────────

class TestDecisionGate:
    def _ctx(self, **kwargs) -> EnrichmentContext:
        ctx = EnrichmentContext(**kwargs)
        return ctx

    def test_l0_suppress_on_allowlist(self):
        ctx = self._ctx(is_allowlisted=True)
        score = 0
        decision = decide(ctx, score, alert_level=5)
        assert decision.level == DecisionLevel.L0_SUPPRESS
        assert decision.skip_llm is True

    def test_l0_suppress_low_score_low_level(self):
        ctx = self._ctx(rule_level=5)
        decision = decide(ctx, score=5, alert_level=5)
        assert decision.level == DecisionLevel.L0_SUPPRESS

    def test_l1_auto_close_benign(self):
        ctx = self._ctx(rule_level=7, ueba_zscore=0.5)
        decision = decide(ctx, score=20, alert_level=7)
        assert decision.level == DecisionLevel.L1_AUTO_CLOSE
        assert decision.skip_llm is True
        assert decision.auto_verdict == "benign"

    def test_l2_triage_middle_band(self):
        ctx = self._ctx(rule_level=10)
        decision = decide(ctx, score=40, alert_level=10)
        assert decision.level == DecisionLevel.L2_TRIAGE
        assert decision.skip_llm is False
        assert decision.fast_llm_only is False

    def test_l3_escalate_high_score(self):
        ctx = self._ctx(rule_level=12, ti_confidence=0.0)
        decision = decide(ctx, score=65, alert_level=12)
        assert decision.level == DecisionLevel.L3_ESCALATE
        assert decision.fast_llm_only is True
        assert decision.auto_verdict == "malicious"

    def test_l4_critical_very_high_score(self):
        ctx = self._ctx(rule_level=15, ti_is_known_bad=True)
        decision = decide(ctx, score=90, alert_level=15)
        assert decision.level == DecisionLevel.L4_CRITICAL
        assert decision.auto_verdict == "malicious"
        assert decision.auto_severity == "critical"

    def test_l4_on_known_bad_crown_jewel(self):
        ctx = self._ctx(rule_level=10, ti_is_known_bad=True, is_crown_jewel=True)
        decision = decide(ctx, score=50, alert_level=10)
        assert decision.level == DecisionLevel.L4_CRITICAL

    def test_l1_not_triggered_with_ti_hit(self):
        ctx = self._ctx(rule_level=7, ti_confidence=0.7)
        decision = decide(ctx, score=20, alert_level=7)
        # Score 20 + ti_hit → should NOT be L1 (ti_confidence > 0 blocks auto-close)
        assert decision.level != DecisionLevel.L1_AUTO_CLOSE

    def test_l1_not_triggered_with_ueba_anomaly(self):
        ctx = self._ctx(rule_level=7, ueba_zscore=3.0)
        decision = decide(ctx, score=20, alert_level=7)
        assert decision.level != DecisionLevel.L1_AUTO_CLOSE


# ─── auto_close.should_auto_close() ─────────────────────────────────────────

class TestAutoClose:
    def _ctx(self, **kwargs) -> EnrichmentContext:
        return EnrichmentContext(**kwargs)

    def test_eligible_deterministic(self):
        ctx = self._ctx(rule_level=7, ueba_zscore=0.5)
        eligible, reason = should_auto_close(ctx, score=15)
        assert eligible is True
        assert "score" in reason

    def test_blocked_by_ti_hit(self):
        ctx = self._ctx(ti_confidence=0.8)
        eligible, reason = should_auto_close(ctx, score=10)
        assert eligible is False
        assert "TI" in reason

    def test_blocked_by_ueba_anomaly(self):
        ctx = self._ctx(ueba_zscore=3.0)
        eligible, reason = should_auto_close(ctx, score=10)
        assert eligible is False
        assert "UEBA" in reason

    def test_blocked_by_vuln_match(self):
        ctx = self._ctx(vuln_matched=True)
        eligible, reason = should_auto_close(ctx, score=10)
        assert eligible is False
        assert "CVE" in reason.lower() or "exploit" in reason.lower()

    def test_blocked_by_crown_jewel(self):
        ctx = self._ctx(is_crown_jewel=True)
        eligible, reason = should_auto_close(ctx, score=10)
        assert eligible is False
        assert "crown" in reason.lower()

    def test_blocked_by_high_score(self):
        ctx = self._ctx(rule_level=7)
        eligible, reason = should_auto_close(ctx, score=50)
        assert eligible is False
        assert "score" in reason.lower()

    def test_eligible_with_benign_llm_verdict(self):
        ctx = self._ctx(rule_level=7)
        eligible, reason = should_auto_close(ctx, score=15, llm_verdict="benign", llm_confidence=0.92)
        assert eligible is True
        assert "benign" in reason.lower()

    def test_blocked_by_low_confidence(self):
        ctx = self._ctx(rule_level=7)
        eligible, reason = should_auto_close(ctx, score=15, llm_verdict="benign", llm_confidence=0.5)
        assert eligible is False
        assert "confidence" in reason.lower()

    def test_blocked_by_non_benign_verdict(self):
        ctx = self._ctx(rule_level=7)
        eligible, reason = should_auto_close(ctx, score=15, llm_verdict="malicious", llm_confidence=0.95)
        assert eligible is False


# ─── Integration: full pipeline ─────────────────────────────────────────────

class TestPipelineIntegration:
    def test_l0_suppress_flow(self):
        """Allowlisted alert → score=0 → L0 → skip LLM."""
        ctx = EnrichmentContext(rule_level=12, is_allowlisted=True)
        score = compute(ctx)
        assert score == 0
        decision = decide(ctx, score, alert_level=12)
        assert decision.level == DecisionLevel.L0_SUPPRESS
        assert decision.skip_llm is True

    def test_l4_critical_flow(self):
        """Known-bad TI on crown jewel → high score → L4 critical."""
        ctx = EnrichmentContext(
            rule_level=13,
            ti_is_known_bad=True,
            is_crown_jewel=True,
            asset_criticality=10,
        )
        score = compute(ctx)
        assert score > 80
        decision = decide(ctx, score, alert_level=13)
        assert decision.level in (DecisionLevel.L3_ESCALATE, DecisionLevel.L4_CRITICAL)

    def test_l2_triage_flow(self):
        """Ambiguous alert → middle score → L2 → full LLM."""
        ctx = EnrichmentContext(
            rule_level=10,
            ueba_zscore=3.0,
            ti_confidence=0.3,
        )
        score = compute(ctx)
        assert 20 < score < 80  # in ambiguous band
        decision = decide(ctx, score, alert_level=10)
        assert decision.level == DecisionLevel.L2_TRIAGE
        assert not decision.skip_llm
        assert not decision.fast_llm_only


# ─── TI Enricher (shared/enrichment/ti.py) ──────────────────────────────────


class TestTIEnricher:
    async def test_no_source_ip_returns_false(self):
        from shared.enrichment.ti import lookup
        mock_session = AsyncMock()
        is_bad, conf, is_kev = await lookup(mock_session, None, "tenant-1")
        assert is_bad is False
        assert conf == 0.0
        assert is_kev is False

    async def test_no_match_returns_false(self):
        from shared.enrichment.ti import lookup
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        is_bad, conf, is_kev = await lookup(mock_session, "1.2.3.4", "tenant-1")
        assert is_bad is False

    async def test_known_bad_ioc_returns_true(self):
        from shared.enrichment.ti import lookup
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = MagicMock(
            threat_score=80.0, confidence=0.95, tags=["malware", "c2"]
        )
        mock_session.execute = AsyncMock(return_value=mock_result)

        is_bad, conf, is_kev = await lookup(mock_session, "10.0.0.1", "tenant-1")
        assert is_bad is True
        assert conf == 0.95
        assert is_kev is False

    async def test_kev_tag_detected(self):
        from shared.enrichment.ti import lookup
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = MagicMock(
            threat_score=90.0, confidence=0.99, tags=["kev", "ransomware"]
        )
        mock_session.execute = AsyncMock(return_value=mock_result)

        is_bad, conf, is_kev = await lookup(mock_session, "192.168.1.1", "tenant-1")
        assert is_bad is True
        assert is_kev is True

    async def test_db_error_returns_false(self):
        from shared.enrichment.ti import lookup
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=Exception("DB down"))

        is_bad, conf, is_kev = await lookup(mock_session, "1.1.1.1", "tenant-1")
        assert is_bad is False
        assert conf == 0.0

    async def test_is_ip_known_bad_convenience(self):
        from shared.enrichment.ti import is_ip_known_bad
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = MagicMock(
            threat_score=90.0, confidence=0.99, tags=[]
        )
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await is_ip_known_bad(mock_session, "10.0.0.1", "tenant-1")
        assert result is True


# ─── Asset Enricher (shared/enrichment/asset.py) ─────────────────────────────


class TestAssetEnricher:
    async def test_no_agent_id_returns_defaults(self):
        from shared.enrichment.asset import get_asset_criticality
        mock_session = AsyncMock()
        crit, is_cj = await get_asset_criticality(mock_session, None, "tenant-1")
        assert crit == 0
        assert is_cj is False

    async def test_asset_not_found_returns_defaults(self):
        from shared.enrichment.asset import get_asset_criticality
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        crit, is_cj = await get_asset_criticality(mock_session, "agent-99", "tenant-1")
        assert crit == 0
        assert is_cj is False

    async def test_normal_asset_returns_criticality(self):
        from shared.enrichment.asset import get_asset_criticality
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = MagicMock(
            criticality=7, labels={}
        )
        mock_session.execute = AsyncMock(return_value=mock_result)

        crit, is_cj = await get_asset_criticality(mock_session, "agent-01", "tenant-1")
        assert crit == 7
        assert is_cj is False

    async def test_criticality_9_is_crown_jewel(self):
        from shared.enrichment.asset import get_asset_criticality
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = MagicMock(
            criticality=9, labels={}
        )
        mock_session.execute = AsyncMock(return_value=mock_result)

        crit, is_cj = await get_asset_criticality(mock_session, "agent-cj", "tenant-1")
        assert crit == 9
        assert is_cj is True

    async def test_label_crown_jewel_override(self):
        from shared.enrichment.asset import get_asset_criticality
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = MagicMock(
            criticality=5, labels={"crown_jewel": True}
        )
        mock_session.execute = AsyncMock(return_value=mock_result)

        crit, is_cj = await get_asset_criticality(mock_session, "agent-cj2", "tenant-1")
        assert crit == 5
        assert is_cj is True

    async def test_db_error_returns_defaults(self):
        from shared.enrichment.asset import get_asset_criticality
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=Exception("DB down"))

        crit, is_cj = await get_asset_criticality(mock_session, "agent-01", "tenant-1")
        assert crit == 0
        assert is_cj is False

    async def test_get_asset_info_returns_metadata(self):
        from shared.enrichment.asset import get_asset_info
        mock_session = AsyncMock()
        mock_asset = MagicMock()
        mock_asset.agent_id = "agent-01"
        mock_asset.agent_name = "web-server-1"
        mock_asset.os_platform = "ubuntu"
        mock_asset.os_version = "22.04"
        mock_asset.criticality = 7
        mock_asset.owner = "infra-team"
        mock_asset.last_seen = None
        mock_asset.groups = ["web", "prod"]

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_asset
        mock_session.execute = AsyncMock(return_value=mock_result)

        info = await get_asset_info(mock_session, "agent-01", "tenant-1")
        assert info is not None
        assert info["agent_id"] == "agent-01"
        assert info["criticality"] == 7


# ─── User Enricher (shared/enrichment/user.py) ───────────────────────────────


class TestUserEnricher:
    """Tests for user risk factor determination."""

    def test_privileged_root(self):
        from shared.enrichment.user import _is_privileged_username
        assert _is_privileged_username("root") is True
        assert _is_privileged_username("ROOT") is True
        assert _is_privileged_username("admin") is True
        assert _is_privileged_username("Administrator") is True

    def test_privileged_domain_admin(self):
        from shared.enrichment.user import _is_privileged_username
        assert _is_privileged_username("DomainAdmin") is True
        assert _is_privileged_username("superuser") is True

    def test_not_privileged_normal_user(self):
        from shared.enrichment.user import _is_privileged_username
        assert _is_privileged_username("john_doe") is False
        assert _is_privileged_username("alice") is False

    def test_service_account_patterns(self):
        from shared.enrichment.user import _is_service_account
        assert _is_service_account("svc-backup") is True
        assert _is_service_account("sql-service") is True
        assert _is_service_account("NT AUTHORITY\\SYSTEM") is True
        assert _is_service_account("NT AUTHORITY\\NETWORK SERVICE") is True
        assert _is_service_account("scanner-prod") is True

    def test_not_service_account(self):
        from shared.enrichment.user import _is_service_account
        assert _is_service_account("john_doe") is False
        assert _is_service_account("admin") is False

    async def test_no_user_name_returns_false(self):
        from shared.enrichment.user import get_user_risk_factors
        mock_session = AsyncMock()
        is_priv, is_svc, is_dormant = await get_user_risk_factors(
            mock_session, None, "tenant-1"
        )
        assert is_priv is False
        assert is_svc is False
        assert is_dormant is False

    async def test_privileged_user_detected(self):
        from shared.enrichment.user import get_user_risk_factors
        mock_session = AsyncMock()
        # Mock the dormant check query
        mock_result = MagicMock()
        mock_result.scalar.return_value = 0  # No historical alerts
        mock_session.execute = AsyncMock(return_value=mock_result)

        is_priv, is_svc, is_dormant = await get_user_risk_factors(
            mock_session, "Administrator", "tenant-1"
        )
        assert is_priv is True
        assert is_svc is False
        assert is_dormant is False

    async def test_service_account_detected(self):
        from shared.enrichment.user import get_user_risk_factors
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar.return_value = 0
        mock_session.execute = AsyncMock(return_value=mock_result)

        is_priv, is_svc, is_dormant = await get_user_risk_factors(
            mock_session, "svc-backup", "tenant-1"
        )
        assert is_priv is False
        assert is_svc is True
        assert is_dormant is False

    async def test_dormant_reactivated_detected(self):
        from shared.enrichment.user import get_user_risk_factors
        mock_session = AsyncMock()

        # First call returns count of old alerts, second returns count of recent
        mock_result1 = MagicMock()
        mock_result1.scalar.return_value = 5  # 5 old alerts
        mock_result2 = MagicMock()
        mock_result2.scalar.return_value = 1  # 1 recent alert (reactivated)

        mock_session.execute = AsyncMock(side_effect=[mock_result1, mock_result2])

        is_priv, is_svc, is_dormant = await get_user_risk_factors(
            mock_session, "john_doe", "tenant-1"
        )
        assert is_priv is False
        assert is_svc is False
        assert is_dormant is True


# ─── UEBA History Enricher (shared/enrichment/ueba_history.py) ────────────────


class TestUebaHistory:
    async def test_no_entities_returns_empty(self):
        from shared.enrichment.ueba_history import get_entity_history
        mock_session = AsyncMock()
        anomalies, max_z = await get_entity_history(
            mock_session, None, None, None, "tenant-1"
        )
        assert anomalies == []
        assert max_z == 0.0

    async def test_returns_anomalies_for_agent(self):
        from shared.enrichment.ueba_history import get_entity_history
        from shared.models.ueba import UebaAnomaly
        from datetime import datetime, timezone

        mock_session = AsyncMock()
        now = datetime.now(timezone.utc)
        mock_anomaly = UebaAnomaly(
            subject_type="agent",
            subject_id="agent-01",
            anomaly_type="alert_count_anomaly",
            score=3.5,
            severity="high",
            description="High alert count",
            detected_at=now,
        )
        mock_anomaly.id = "anom-001"

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_anomaly]
        mock_session.execute = AsyncMock(return_value=mock_result)

        anomalies, max_z = await get_entity_history(
            mock_session, "agent-01", None, None, "tenant-1"
        )
        assert len(anomalies) == 1
        assert anomalies[0]["z_score"] == 3.5
        assert max_z == 3.5

    async def test_max_zscore_across_entities(self):
        from shared.enrichment.ueba_history import get_entity_history
        from shared.models.ueba import UebaAnomaly
        from datetime import datetime, timezone

        mock_session = AsyncMock()
        now = datetime.now(timezone.utc)

        a1 = UebaAnomaly(subject_type="agent", subject_id="a1",
                         anomaly_type="test", score=2.0, severity="medium",
                         detected_at=now)
        a1.id = "anom-001"
        a2 = UebaAnomaly(subject_type="user", subject_id="u1",
                         anomaly_type="test", score=5.0, severity="critical",
                         detected_at=now)
        a2.id = "anom-002"

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [a1, a2]
        mock_session.execute = AsyncMock(return_value=mock_result)

        anomalies, max_z = await get_entity_history(
            mock_session, "agent-01", "user-01", None, "tenant-1"
        )
        assert len(anomalies) == 2
        assert max_z == 5.0

    async def test_db_error_returns_empty(self):
        from shared.enrichment.ueba_history import get_entity_history
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=Exception("DB down"))

        anomalies, max_z = await get_entity_history(
            mock_session, "agent-01", None, None, "tenant-1"
        )
        assert anomalies == []
        assert max_z == 0.0

    async def test_count_anomalies_returns_count(self):
        from shared.enrichment.ueba_history import count_anomalies
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar.return_value = 3
        mock_session.execute = AsyncMock(return_value=mock_result)

        count = await count_anomalies(mock_session, "agent-01", None, None, "tenant-1")
        assert count == 3


# ─── Full Pipeline with All Enrichers ────────────────────────────────────────


class TestFullPipelineWireup:
    """Verify that the pipeline correctly wires all enricher modules."""

    def test_pipeline_imports_all_modules(self):
        """All enricher modules are importable."""
        from shared.enrichment import ti, asset, user, ueba_history
        from shared.enrichment import geoip, vuln_correlate, watchlists
        from shared.enrichment import risk_score, decision, auto_close
        from shared.enrichment.pipeline import run, enrich_alert

        assert callable(run)
        assert callable(enrich_alert)

    def test_pipeline_exports_match_origin(self):
        """enrich_alert is the same callable as run for backward compat."""
        from shared.enrichment.pipeline import run, enrich_alert
        assert enrich_alert is run

    async def test_pipeline_allowlist_skips_io(self):
        """When allowlisted, pipeline returns immediately without I/O."""
        from shared.enrichment.pipeline import run
        from shared.enrichment.watchlists import WatchlistCache

        mock_session = AsyncMock()
        mock_redis = MagicMock()

        # Configure watchlist to flag as allowlisted
        mock_wl = MagicMock(spec=WatchlistCache)
        mock_wl.is_allowlisted.return_value = True
        mock_wl.is_blocklisted.return_value = (False, 0.0)
        mock_wl.is_crown_jewel.return_value = False

        # Minimal alert-like object
        alert = MagicMock()
        alert.rule_level = 10
        alert.source_ip = "10.0.0.1"
        alert.user_name = "admin"
        alert.agent_id = "agent-01"
        alert.mitre_technique = ""

        ctx = await run(alert, "tenant-1", mock_session, redis_client=mock_redis,
                        watchlist_cache=mock_wl)
        assert ctx.is_allowlisted is True
        assert ctx.rule_level == 10

    async def test_pipeline_with_all_enrichers_populates_context(self):
        """All enrichers run and populate fields without crashing."""
        from shared.enrichment.pipeline import run
        from shared.enrichment.watchlists import WatchlistCache

        mock_session = AsyncMock()
        mock_redis = MagicMock()

        mock_wl = MagicMock(spec=WatchlistCache)
        mock_wl.is_allowlisted.return_value = False
        mock_wl.is_blocklisted.return_value = (False, 0.0)
        mock_wl.is_crown_jewel.return_value = False

        alert = MagicMock()
        alert.rule_level = 10
        alert.source_ip = "203.0.113.1"
        alert.user_name = "jdoe"
        alert.agent_id = "agent-01"
        alert.mitre_technique = "T1486"
        alert.rule_description = "Suspicious activity"
        alert.rule_groups = "web,attack"
        alert.rule_cve = None

        # Each enricher will either fail-open (no actual DB data) or return defaults
        ctx = await run(alert, "tenant-1", mock_session, redis_client=mock_redis,
                        watchlist_cache=mock_wl)
        assert ctx.rule_level == 10
        assert ctx.mitre_high_impact is True  # T1486 is ransomware
        # Not allowlisted
        assert ctx.is_allowlisted is False
