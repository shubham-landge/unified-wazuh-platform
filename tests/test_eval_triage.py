"""Tests for the A/B Triage Evaluation Harness metrics and promotion gate."""
from __future__ import annotations

import pytest

from scripts.eval_triage import (
    EvalSample,
    EvalResult,
    EvalMetrics,
    EvalSummary,
    accumulate_metrics,
    compute_metrics,
    promotion_gate,
    _within_one_band,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sample(
    alert_id: str,
    true_verdict: str = "malicious",
    true_severity: str = "high",
    is_tp: bool = True,
    mitre: list[str] | None = None,
) -> EvalSample:
    return EvalSample(
        alert_id=alert_id,
        alert_data={"rule_id": 1000},
        ground_truth={
            "verdict": true_verdict,
            "severity": true_severity,
            "is_true_positive": is_tp,
            "mitre_techniques": mitre or [],
        },
    )


def _make_result(
    sample_id: str,
    verdict: str = "malicious",
    severity: str = "high",
    mitre: set[str] | None = None,
    confidence: float = 0.9,
    latency_ms: float = 100.0,
    json_valid: bool = True,
    error: str | None = None,
) -> EvalResult:
    return EvalResult(
        sample_id=sample_id,
        predicted_verdict=verdict,
        predicted_severity=severity,
        predicted_mitre=mitre or set(),
        predicted_confidence=confidence,
        latency_ms=latency_ms,
        json_valid=json_valid,
        raw_response='{"verdict": "' + verdict + '"}',
        error=error,
    )


# ---------------------------------------------------------------------------
# _within_one_band
# ---------------------------------------------------------------------------


class TestWithinOneBand:
    def test_exact_match(self):
        assert _within_one_band("low", "low") is True
        assert _within_one_band("critical", "critical") is True

    def test_adjacent_bands(self):
        assert _within_one_band("low", "medium") is True
        assert _within_one_band("medium", "high") is True
        assert _within_one_band("high", "critical") is True

    def test_two_bands_away(self):
        assert _within_one_band("low", "high") is False
        assert _within_one_band("medium", "critical") is False
        assert _within_one_band("low", "critical") is False

    def test_unknown_band(self):
        assert _within_one_band("unknown", "medium") is False
        assert _within_one_band("medium", "unknown") is False

    def test_case_insensitive(self):
        assert _within_one_band("HIGH", "high") is True
        assert _within_one_band("Medium", "high") is True


# ---------------------------------------------------------------------------
# accumulate_metrics
# ---------------------------------------------------------------------------


class TestAccumulateMetrics:
    def test_correct_verdict_tp(self):
        metrics = EvalMetrics(model="test")
        sample = _make_sample("s1", true_verdict="malicious", is_tp=True)
        result = _make_result("s1", verdict="malicious")
        accumulate_metrics(metrics, sample, result)

        assert metrics.total == 1
        assert metrics.correct_verdicts == 1
        assert metrics.true_positive_total == 1
        assert metrics.true_negative_total == 0
        assert metrics.false_negatives == 0
        assert metrics.false_positives == 0

    def test_false_negative(self):
        metrics = EvalMetrics(model="test")
        sample = _make_sample("s1", true_verdict="malicious", is_tp=True)
        result = _make_result("s1", verdict="benign")
        accumulate_metrics(metrics, sample, result)

        assert metrics.total == 1
        assert metrics.correct_verdicts == 0
        assert metrics.false_negatives == 1
        assert metrics.true_positive_total == 1

    def test_false_positive(self):
        metrics = EvalMetrics(model="test")
        sample = _make_sample("s1", true_verdict="benign", is_tp=False)
        result = _make_result("s1", verdict="malicious")
        accumulate_metrics(metrics, sample, result)

        assert metrics.total == 1
        assert metrics.correct_verdicts == 0
        assert metrics.false_positives == 1
        assert metrics.true_negative_total == 1

    def test_json_invalid_counts(self):
        metrics = EvalMetrics(model="test")
        sample = _make_sample("s1")
        result = _make_result("s1", json_valid=False)
        accumulate_metrics(metrics, sample, result)

        assert metrics.json_valid == 0

    def test_error_tracking(self):
        metrics = EvalMetrics(model="test")
        sample = _make_sample("s1")
        result = _make_result("s1", error="timeout")
        accumulate_metrics(metrics, sample, result)

        assert len(metrics.errors) == 1
        assert metrics.errors[0] == "timeout"

    def test_latency_accumulation(self):
        metrics = EvalMetrics(model="test")
        for i in range(3):
            sample = _make_sample(f"s{i}")
            result = _make_result(f"s{i}", latency_ms=float((i + 1) * 100))
            accumulate_metrics(metrics, sample, result)

        assert metrics.latencies == [100.0, 200.0, 300.0]
        assert metrics.latency_p50_ms == 200.0
        assert metrics.latency_p95_ms == 300.0

    def test_severity_exact_and_within_one(self):
        metrics = EvalMetrics(model="test")
        # exact match
        sample = _make_sample("s1", true_severity="high")
        result = _make_result("s1", severity="high")
        accumulate_metrics(metrics, sample, result)
        assert metrics.severity_matches == 1
        assert metrics.severity_within_one == 1

        # within one but not exact (medium -> high)
        sample2 = _make_sample("s2", true_severity="medium")
        result2 = _make_result("s2", severity="high")
        accumulate_metrics(metrics, sample2, result2)
        assert metrics.severity_matches == 1  # not incremented
        assert metrics.severity_within_one == 2  # incremented

        # two bands away (low -> critical)
        sample3 = _make_sample("s3", true_severity="low")
        result3 = _make_result("s3", severity="critical")
        accumulate_metrics(metrics, sample3, result3)
        assert metrics.severity_within_one == 2  # not incremented

    def test_mitre_precision_recall(self):
        metrics = EvalMetrics(model="test")
        sample = _make_sample("s1", mitre=["T1110", "T1190"])
        result = _make_result("s1", mitre={"T1110"})
        accumulate_metrics(metrics, sample, result)

        assert metrics.mitre_tp == 1  # T1110 was correct
        assert metrics.mitre_pred == 1  # we predicted 1 technique
        assert metrics.mitre_true == 2  # there were 2 true techniques
        assert metrics.mitre_precision == 1.0  # 1/1
        assert metrics.mitre_recall == 0.5  # 1/2

    def test_brier_score_tp(self):
        metrics = EvalMetrics(model="test")
        # True positive, predicted malicious with confidence 0.8
        sample = _make_sample("s1", is_tp=True, true_verdict="malicious")
        result = _make_result("s1", verdict="malicious", confidence=0.8)
        accumulate_metrics(metrics, sample, result)

        # P(malicious) = 0.8, outcome = 1.0, brier = (0.8 - 1.0)^2 = 0.04
        assert metrics.brier_sum == pytest.approx(0.04)

    def test_brier_score_tn_benign(self):
        metrics = EvalMetrics(model="test")
        # True negative, predicted benign with confidence 0.7
        # P(malicious) = 1 - 0.7 = 0.3, outcome = 0.0
        sample = _make_sample("s1", is_tp=False, true_verdict="benign")
        result = _make_result("s1", verdict="benign", confidence=0.7)
        accumulate_metrics(metrics, sample, result)

        assert metrics.brier_sum == pytest.approx(0.09)  # (0.3 - 0.0)^2

    def test_brier_score_fn(self):
        metrics = EvalMetrics(model="test")
        # False negative: true is malicious, predicted benign with confidence 0.9
        # P(malicious) = 1 - 0.9 = 0.1, outcome = 1.0
        sample = _make_sample("s1", is_tp=True, true_verdict="malicious")
        result = _make_result("s1", verdict="benign", confidence=0.9)
        accumulate_metrics(metrics, sample, result)

        assert metrics.brier_sum == pytest.approx(0.81)  # (0.1 - 1.0)^2


# ---------------------------------------------------------------------------
# compute_metrics
# ---------------------------------------------------------------------------


class TestComputeMetrics:
    def test_empty_results(self):
        summary = compute_metrics([], model_name="empty-test")
        assert summary.total_samples == 0
        assert summary.verdict_accuracy == 0.0
        assert summary.fn_rate == 0.0
        assert summary.fp_rate == 0.0
        assert summary.confidence_brier == 0.0
        assert summary.latency_p50_ms == 0.0
        assert summary.latency_p95_ms == 0.0

    def test_perfect_predictions(self):
        results = [
            (
                _make_sample("s1", true_verdict="malicious", is_tp=True,
                             true_severity="high", mitre=["T1110"]),
                _make_result("s1", verdict="malicious", severity="high",
                             mitre={"T1110"}, confidence=0.95, latency_ms=100),
            ),
            (
                _make_sample("s2", true_verdict="benign", is_tp=False,
                             true_severity="low", mitre=[]),
                _make_result("s2", verdict="benign", severity="low",
                             mitre=set(), confidence=0.90, latency_ms=50),
            ),
        ]
        summary = compute_metrics(results, model_name="perfect")

        assert summary.model == "perfect"
        assert summary.total_samples == 2
        assert summary.verdict_accuracy == 1.0
        assert summary.fn_rate == 0.0
        assert summary.fp_rate == 0.0
        assert summary.severity_agreement == 1.0
        assert summary.severity_within_one_band == 1.0
        assert summary.mitre_precision == 1.0
        assert summary.mitre_recall == 1.0
        assert summary.json_validity == 1.0

    def test_mixed_results(self):
        results = [
            # TP correctly classified
            (
                _make_sample("s1", true_verdict="malicious", is_tp=True,
                             true_severity="high", mitre=["T1110"]),
                _make_result("s1", verdict="malicious", severity="high",
                             mitre={"T1110"}, confidence=0.9),
            ),
            # FN — missed threat
            (
                _make_sample("s2", true_verdict="malicious", is_tp=True,
                             true_severity="critical", mitre=["T1190"]),
                _make_result("s2", verdict="benign", severity="medium",
                             mitre=set(), confidence=0.3),
            ),
            # TN correctly classified
            (
                _make_sample("s3", true_verdict="benign", is_tp=False,
                             true_severity="low", mitre=[]),
                _make_result("s3", verdict="benign", severity="low",
                             mitre=set(), confidence=0.8),
            ),
            # FP — false alarm
            (
                _make_sample("s4", true_verdict="benign", is_tp=False,
                             true_severity="low", mitre=[]),
                _make_result("s4", verdict="malicious", severity="high",
                             mitre={"T1078"}, confidence=0.7, json_valid=False),
            ),
        ]
        summary = compute_metrics(results, model_name="mixed")

        assert summary.total_samples == 4
        assert summary.verdict_accuracy == 0.5  # 2/4 correct
        assert summary.fn_rate == 0.5  # 1 FN out of 2 TP samples
        assert summary.fp_rate == 0.5  # 1 FP out of 2 TN samples
        assert summary.json_validity == 0.75  # 3/4 valid
        assert summary.severity_agreement == 0.5  # s1 and s3 match exactly
        assert summary.severity_within_one_band == 0.5  # s1 and s3 within one; s2 (medium→critical=2 bands) and s4 are not

    def test_division_by_zero_protection(self):
        """Metrics with zero denominators should not crash."""
        metrics = EvalMetrics(model="safe")
        # No true positives -> fn_rate = 0/1 = 0.0 (guarded)
        assert metrics.fn_rate == 0.0
        # No true negatives -> fp_rate = 0/1 = 0.0 (guarded)
        assert metrics.fp_rate == 0.0
        # No predictions -> mitre_precision = 0/1 = 0.0
        assert metrics.mitre_precision == 0.0
        assert metrics.mitre_recall == 0.0
        # latencies empty -> p50/p95 = 0.0
        assert metrics.latency_p50_ms == 0.0
        assert metrics.latency_p95_ms == 0.0


# ---------------------------------------------------------------------------
# promotion_gate
# ---------------------------------------------------------------------------


class TestPromotionGate:
    def test_passes_when_below_baselines(self):
        summary = EvalSummary(
            model="candidate",
            total_samples=100,
            verdict_accuracy=0.95,
            fn_rate=0.02,
            fp_rate=0.03,
            severity_agreement=0.7,
            severity_within_one_band=0.9,
            mitre_precision=0.8,
            mitre_recall=0.7,
            confidence_brier=0.05,
            json_validity=0.98,
            latency_p50_ms=200.0,
            latency_p95_ms=500.0,
            errors=0,
        )
        assert promotion_gate(summary, baseline_fn=0.05, baseline_fp=0.05) is True

    def test_fails_on_fn_exceeds(self):
        summary = EvalSummary(
            model="candidate",
            total_samples=100,
            verdict_accuracy=0.9,
            fn_rate=0.10,
            fp_rate=0.03,
            severity_agreement=0.7,
            severity_within_one_band=0.9,
            mitre_precision=0.8,
            mitre_recall=0.7,
            confidence_brier=0.05,
            json_validity=0.98,
            latency_p50_ms=200.0,
            latency_p95_ms=500.0,
            errors=0,
        )
        # fn_rate 0.10 > baseline_fn 0.05
        assert promotion_gate(summary, baseline_fn=0.05, baseline_fp=0.05) is False

    def test_passes_on_fn_equal(self):
        summary = EvalSummary(
            model="candidate",
            total_samples=100,
            verdict_accuracy=0.9,
            fn_rate=0.05,
            fp_rate=0.03,
            severity_agreement=0.7,
            severity_within_one_band=0.9,
            mitre_precision=0.8,
            mitre_recall=0.7,
            confidence_brier=0.05,
            json_validity=0.98,
            latency_p50_ms=200.0,
            latency_p95_ms=500.0,
            errors=0,
        )
        # fn_rate 0.05 == baseline_fn 0.05 (allowed)
        assert promotion_gate(summary, baseline_fn=0.05, baseline_fp=0.05) is True

    def test_fails_on_fp_exceeds_margin(self):
        summary = EvalSummary(
            model="candidate",
            total_samples=100,
            verdict_accuracy=0.9,
            fn_rate=0.02,
            fp_rate=0.12,
            severity_agreement=0.7,
            severity_within_one_band=0.9,
            mitre_precision=0.8,
            mitre_recall=0.7,
            confidence_brier=0.05,
            json_validity=0.98,
            latency_p50_ms=200.0,
            latency_p95_ms=500.0,
            errors=0,
        )
        # fp_rate 0.12 > baseline_fp 0.05 + FP_MARGIN 0.05 = 0.10
        assert promotion_gate(summary, baseline_fn=0.05, baseline_fp=0.05) is False

    def test_passes_on_fp_equal_to_margin(self):
        summary = EvalSummary(
            model="candidate",
            total_samples=100,
            verdict_accuracy=0.9,
            fn_rate=0.02,
            fp_rate=0.10,
            severity_agreement=0.7,
            severity_within_one_band=0.9,
            mitre_precision=0.8,
            mitre_recall=0.7,
            confidence_brier=0.05,
            json_validity=0.98,
            latency_p50_ms=200.0,
            latency_p95_ms=500.0,
            errors=0,
        )
        # fp_rate 0.10 == baseline_fp 0.05 + FP_MARGIN 0.05 = 0.10 (allowed)
        assert promotion_gate(summary, baseline_fn=0.05, baseline_fp=0.05) is True

    def test_fp_exact_equal_margin_edge(self):
        """fp at exactly the boundary should pass."""
        summary = EvalSummary(
            model="candidate",
            total_samples=100,
            verdict_accuracy=0.9,
            fn_rate=0.0,
            fp_rate=0.05,
            severity_agreement=0.7,
            severity_within_one_band=0.9,
            mitre_precision=0.8,
            mitre_recall=0.7,
            confidence_brier=0.05,
            json_validity=0.98,
            latency_p50_ms=200.0,
            latency_p95_ms=500.0,
            errors=0,
        )
        # baseline_fn=0.0, baseline_fp=0.0, FP_MARGIN=0.05
        # fn_rate 0.0 <= 0.0 ✓, fp_rate 0.05 <= 0.0+0.05 ✓
        assert promotion_gate(summary, baseline_fn=0.0, baseline_fp=0.0) is True

    def test_fn_and_fp_both_fail(self):
        """When both rates exceed baselines, gate should fail."""
        summary = EvalSummary(
            model="bad-model",
            total_samples=100,
            verdict_accuracy=0.5,
            fn_rate=0.30,
            fp_rate=0.40,
            severity_agreement=0.5,
            severity_within_one_band=0.7,
            mitre_precision=0.5,
            mitre_recall=0.5,
            confidence_brier=0.20,
            json_validity=0.6,
            latency_p50_ms=5000.0,
            latency_p95_ms=20000.0,
            errors=5,
        )
        assert promotion_gate(summary, baseline_fn=0.05, baseline_fp=0.05) is False
