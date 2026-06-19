"""Tests for the shared enrichment package (risk_score, decision gate, auto_close).

All tests are pure unit tests — no DB, no Redis, no network required.
"""
from __future__ import annotations

import pytest
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
