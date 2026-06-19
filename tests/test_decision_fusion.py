"""Tests for shared.enrichment.decision_fusion — hybrid decision fusion.

All tests are pure unit tests — no DB, no Redis, no network required.
"""
from __future__ import annotations

import pytest

from shared.enrichment.decision_fusion import fuse_verdict
from shared.enrichment.risk_score import EnrichmentContext


# ─── helpers ─────────────────────────────────────────────────────────────────

def _make_llm_verdict(
    severity: str = "medium",
    confidence: float = 0.5,
    **extra,
) -> dict:
    return {"severity": severity, "confidence": confidence, **extra}


# ─── Rule 1: benign → suspicious when TI says known-bad ────────────────────

class TestRule1_BenignToSuspicious:
    def test_ti_known_bad_overrides_benign(self):
        """Benign + TI known-bad → severity becomes 'suspicious', confidence ≥ 0.8."""
        ctx = EnrichmentContext(ti_is_known_bad=True)
        result = fuse_verdict(
            _make_llm_verdict(severity="benign", confidence=0.5),
            ctx,
            risk_score=15,
        )
        assert result["severity"] == "suspicious"
        assert result["confidence"] >= 0.8
        assert result["fusion_applied"] is True
        assert any("is_known_bad" in o for o in result["fusion_overrides"])

    def test_ti_not_known_bad_no_override(self):
        """Benign without TI known-bad → no fusion override."""
        ctx = EnrichmentContext(ti_is_known_bad=False)
        result = fuse_verdict(
            _make_llm_verdict(severity="benign", confidence=0.5),
            ctx,
            risk_score=15,
        )
        assert result["severity"] == "benign"
        assert result["fusion_applied"] is False


# ─── Rule 2: malicious confidence haircut ──────────────────────────────────

class TestRule2_MaliciousConfidenceHaircut:
    def test_low_signals_downgrade_confidence(self):
        """Malicious + low UEBA + no TI + low risk → confidence -0.2."""
        ctx = EnrichmentContext(ueba_zscore=0.5, ti_confidence=0.0)
        result = fuse_verdict(
            _make_llm_verdict(severity="malicious", confidence=0.9),
            ctx,
            risk_score=10,
        )
        assert result["confidence"] == pytest.approx(0.7)  # 0.9 - 0.2
        assert result["fusion_applied"] is True

    def test_high_ueba_skips_haircut(self):
        """Malicious + high UEBA → confidence unchanged."""
        ctx = EnrichmentContext(ueba_zscore=3.0, ti_confidence=0.0)
        result = fuse_verdict(
            _make_llm_verdict(severity="malicious", confidence=0.9),
            ctx,
            risk_score=10,
        )
        assert result["confidence"] == pytest.approx(0.9)
        assert result["fusion_applied"] is False

    def test_confidence_floor_on_haircut(self):
        """Confidence haircut should not go below 0.0."""
        ctx = EnrichmentContext(ueba_zscore=0.0, ti_confidence=0.0)
        result = fuse_verdict(
            _make_llm_verdict(severity="malicious", confidence=0.1),
            ctx,
            risk_score=5,
        )
        assert result["confidence"] >= 0.0
        assert result["fusion_applied"] is True


# ─── Rule 3: boost confidence on high risk ─────────────────────────────────

class TestRule3_BoostConfidence:
    def test_high_risk_boosts_low_confidence(self):
        """Risk score ≥ 60 + confidence < 0.7 → boosted to 0.75."""
        ctx = EnrichmentContext()
        result = fuse_verdict(
            _make_llm_verdict(severity="malicious", confidence=0.5),
            ctx,
            risk_score=75,
        )
        assert result["confidence"] == pytest.approx(0.75)
        assert result["fusion_applied"] is True

    def test_high_risk_does_not_boost_already_high_confidence(self):
        """Risk score ≥ 60 + confidence ≥ 0.7 → no boost."""
        ctx = EnrichmentContext()
        result = fuse_verdict(
            _make_llm_verdict(severity="malicious", confidence=0.8),
            ctx,
            risk_score=75,
        )
        assert result["confidence"] == pytest.approx(0.8)
        assert result["fusion_applied"] is False


# ─── Rule 4: critical → high on low risk -----------------------------------

class TestRule4_CriticalDowngrade:
    def test_critical_downgraded_on_low_risk(self):
        """Critical + risk < 40 → severity becomes 'high'."""
        ctx = EnrichmentContext()
        result = fuse_verdict(
            _make_llm_verdict(severity="critical", confidence=0.9),
            ctx,
            risk_score=25,
        )
        assert result["severity"] == "high"
        assert result["fusion_applied"] is True

    def test_critical_preserved_high_risk(self):
        """Critical + risk ≥ 40 → severity stays 'critical'."""
        ctx = EnrichmentContext()
        result = fuse_verdict(
            _make_llm_verdict(severity="critical", confidence=0.9),
            ctx,
            risk_score=50,
        )
        assert result["severity"] == "critical"
        assert result["fusion_applied"] is False


# ─── General behaviour ─────────────────────────────────────────────────────

class TestGeneral:
    def test_does_not_mutate_original_dict(self):
        """The original llm_verdict dict is never modified."""
        ctx = EnrichmentContext(ti_is_known_bad=True)
        original = _make_llm_verdict(severity="benign", confidence=0.5)
        original_copy = dict(original)
        fuse_verdict(original, ctx, risk_score=15)
        assert original == original_copy

    def test_missing_severity_and_confidence_defaults(self):
        """Missing severity/confidence are handled gracefully with defaults."""
        ctx = EnrichmentContext()
        result = fuse_verdict({}, ctx, risk_score=10)
        assert result["severity"] == "medium"
        assert result["confidence"] == pytest.approx(0.5)
        assert result["fusion_applied"] is False

    def test_multiple_rules_can_trigger(self):
        """Multiple rules can fire on the same verdict."""
        ctx = EnrichmentContext(ti_is_known_bad=True, ueba_zscore=0.3, ti_confidence=0.0)
        result = fuse_verdict(
            _make_llm_verdict(severity="benign", confidence=0.5),
            ctx,
            risk_score=10,
        )
        assert result["severity"] == "suspicious"  # rule 1
        assert result["confidence"] >= 0.8  # rule 1 (rule 2 doesn't apply — severity is not malicious)
        assert result["fusion_applied"] is True
        assert len(result["fusion_overrides"]) >= 1
