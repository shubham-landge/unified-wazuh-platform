"""Tests for confidence calibration and decision fusion.

Covers:
  - Temperature scaling with various T values.
  - Calibration curve construction from (confidence, outcome) history.
  - Insufficient-data pass-through (fail-open).
  - Decision fusion: unanimous, split, weighted, empty/single.
  - ConfidenceHistory ring buffer (append, all, clear, is_ready).
  - Integration: full calibrate() pipeline with curve.
"""
from __future__ import annotations

import math

import pytest

from shared.enrichment.calibration import (
    CalibratedConfidence,
    ConfidenceHistory,
    _apply_temperature,
    calibrate,
    fuse_decisions,
    update_calibration_curve,
)


# ── Temperature scaling ──────────────────────────────────────────────────────


class TestTemperatureScaling:
    def test_t1_no_change(self):
        """T=1 should leave mid-range confidence approximately unchanged."""
        result = _apply_temperature(0.7, 1.0)
        assert abs(result - 0.7) < 0.02  # nearly identical

    def test_t_lt_1_sharpens(self):
        """T<1 pushes confidence toward extremes (0 or 1)."""
        neutral = _apply_temperature(0.7, 1.0)
        sharp = _apply_temperature(0.7, 0.5)
        # Sharpening moves away from 0.5
        assert abs(sharp - 0.5) > abs(neutral - 0.5) or sharp >= 0.69

    def test_t_gt_1_softens(self):
        """T>1 pulls confidence toward 0.5 (softer, less extreme)."""
        neutral = _apply_temperature(0.9, 1.0)
        soft = _apply_temperature(0.9, 2.0)
        # Softening moves toward 0.5
        assert abs(soft - 0.5) < abs(neutral - 0.5)

    def test_edge_values_handled(self):
        """Edge values (0, 1) should not produce math errors."""
        result_lo = _apply_temperature(0.0, 1.0)
        result_hi = _apply_temperature(1.0, 1.0)
        assert 0.0 <= result_lo <= 1.0
        assert 0.0 <= result_hi <= 1.0

    def test_temperature_scaling_is_monotonic(self):
        """Higher raw confidence → higher calibrated confidence."""
        a = _apply_temperature(0.3, 1.0)
        b = _apply_temperature(0.6, 1.0)
        c = _apply_temperature(0.9, 1.0)
        assert a < b < c


# ── Calibration curve construction ───────────────────────────────────────────


class TestUpdateCalibrationCurve:
    def test_sufficient_data_returns_curve(self):
        """With >= 20 entries, a valid curve dict is returned."""
        history = [(0.5, (i % 3 == 0)) for i in range(30)]  # ~33% accuracy
        curve = update_calibration_curve(history, n_bins=5)
        assert isinstance(curve, dict)
        assert len(curve) <= 5
        for idx, (center, acc) in curve.items():
            assert isinstance(idx, int)
            assert 0.0 <= center <= 1.0
            assert 0.0 <= acc <= 1.0

    def test_insufficient_data_returns_empty(self):
        """Fewer than 20 entries → empty dict (fail-open)."""
        history = [(0.5, True)] * 10
        curve = update_calibration_curve(history)
        assert curve == {}

    def test_curve_reflects_accuracy(self):
        """Synthetic data: 80% correct in high-confidence bin, 20% in low."""
        history = []
        # High-confidence (0.8–1.0) entries, 80% correct
        for i in range(50):
            conf = 0.8 + (i % 10) * 0.02
            history.append((conf, i % 5 != 0))  # 80% correct
        # Low-confidence (0.1–0.3) entries, 20% correct
        for i in range(50):
            conf = 0.1 + (i % 10) * 0.02
            history.append((conf, i % 5 == 0))  # 20% correct

        curve = update_calibration_curve(history, n_bins=4)
        bins_by_center = sorted(curve.items(), key=lambda x: x[1][0])

        # Lowest bin should have low accuracy, highest bin should have high accuracy
        low_acc = bins_by_center[0][1][1]
        high_acc = bins_by_center[-1][1][1]
        assert high_acc > low_acc, f"Expected high_acc > low_acc, got {high_acc} vs {low_acc}"


# ── calibrate() function ─────────────────────────────────────────────────────


class TestCalibrate:
    def test_with_empty_curve_returns_scaled(self):
        """When curve is empty, temperature-scaled value is returned unchanged."""
        result = calibrate(0.7, {}, temperature=2.0)
        assert isinstance(result, CalibratedConfidence)
        assert result.raw_confidence == 0.7
        assert result.bin_index == -1
        # Temperature-scaled value for T=2 on 0.7 should be > 0.5 but < 0.7
        assert 0.5 < result.calibrated_confidence < 0.7

    def test_with_curve_interpolates(self):
        """With a valid curve, the result is bin-interpolated."""
        # Build a simple 2-bin curve
        curve = {0: (0.3, 0.2), 1: (0.7, 0.8)}
        result = calibrate(0.5, curve, temperature=1.0)
        assert isinstance(result, CalibratedConfidence)
        # Should interpolate between bin 0 (acc=0.2) and bin 1 (acc=0.8)
        assert 0.2 <= result.calibrated_confidence <= 0.8
        assert result.bin_index >= 0

    def test_insufficient_data_pass_through(self):
        """Without calibration data, raw confidence is returned (fail-open)."""
        result = calibrate(0.85, {}, temperature=1.0)
        # T=1 on 0.85 is approximately 0.85
        assert abs(result.calibrated_confidence - 0.85) < 0.02
        assert result.bin_index == -1


# ── Decision fusion ──────────────────────────────────────────────────────────


class TestFuseDecisions:
    def test_unanimous_returns_winner(self):
        """All votes for same label → that label wins."""
        decisions = [("benign", 0.9), ("benign", 0.8), ("benign", 0.7)]
        winner, conf = fuse_decisions(decisions)
        assert winner == "benign"
        assert 0.7 <= conf <= 0.9

    def test_split_returns_majority(self):
        """Mixed labels → highest weighted vote wins."""
        decisions = [
            ("malicious", 0.9),
            ("malicious", 0.8),
            ("benign", 0.3),
        ]
        winner, conf = fuse_decisions(decisions)
        assert winner == "malicious"
        assert conf > 0.5

    def test_weighted_votes_tip_result(self):
        """Custom weights influence the outcome — benign wins uniform, malicious wins weighted."""
        decisions = [
            ("benign", 0.9),
            ("malicious", 0.4),
            ("malicious", 0.4),
        ]
        # Uniform weights → benign wins (0.9 > 0.4+0.4=0.8)
        winner_uniform, _ = fuse_decisions(decisions)
        assert winner_uniform == "benign"

        # Weighted toward malicious → malicious wins (0.9*0.1=0.09 < 0.4+0.4=0.8)
        winner_weighted, _ = fuse_decisions(decisions, weights=[0.1, 1.0, 1.0])
        assert winner_weighted == "malicious"

    def test_single_decision_returns_itself(self):
        """Single decision → that label wins."""
        winner, conf = fuse_decisions([("critical", 0.95)])
        assert winner == "critical"
        assert conf == pytest.approx(0.95)

    def test_empty_decisions_raises(self):
        """Empty list → ValueError."""
        with pytest.raises(ValueError):
            fuse_decisions([])

    def test_mismatched_weights_raises(self):
        """Different number of weights vs decisions → ValueError."""
        decisions = [("a", 0.5), ("b", 0.5)]
        with pytest.raises(ValueError):
            fuse_decisions(decisions, weights=[1.0])


# ── ConfidenceHistory ring buffer ────────────────────────────────────────────


class TestConfidenceHistory:
    def test_append_and_all(self):
        """Entries are appended and retrievable."""
        hist = ConfidenceHistory(maxlen=100)
        hist.append(0.8, True)
        hist.append(0.3, False)
        entries = hist.all()
        assert entries == [(0.8, True), (0.3, False)]

    def test_ring_buffer_eviction(self):
        """When maxlen exceeded, oldest entries are dropped."""
        hist = ConfidenceHistory(maxlen=5)
        for i in range(10):
            hist.append(float(i) / 10, i % 2 == 0)
        entries = hist.all()
        assert len(entries) == 5
        # Oldest should be 5/10, not 0/10
        assert entries[0][0] == pytest.approx(0.5)

    def test_is_ready_requires_min_samples(self):
        """is_ready_for_calibration returns False until enough data."""
        hist = ConfidenceHistory(maxlen=100)
        for i in range(15):
            hist.append(0.5, True)
        assert hist.is_ready_for_calibration is False
        for i in range(10):
            hist.append(0.5, True)
        assert hist.is_ready_for_calibration is True

    def test_clear_empties_buffer(self):
        """clear() removes all entries."""
        hist = ConfidenceHistory(maxlen=100)
        hist.append(0.7, True)
        hist.append(0.4, False)
        assert len(hist) == 2
        hist.clear()
        assert len(hist) == 0
        assert hist.all() == []

    def test_len_reflects_buffer_size(self):
        """__len__ returns correct count."""
        hist = ConfidenceHistory(maxlen=100)
        assert len(hist) == 0
        hist.append(0.5, True)
        assert len(hist) == 1


# ── Integration ──────────────────────────────────────────────────────────────


class TestCalibrationIntegration:
    def test_full_pipeline_with_synthetic_data(self):
        """Build curve from history, then calibrate a new confidence."""
        # Create history: low confidence = low accuracy, high = high accuracy
        hist = ConfidenceHistory()
        for _ in range(50):
            hist.append(0.15, True)   # low confidence, somewhat correct
            hist.append(0.15, False)
            hist.append(0.85, True)   # high confidence, mostly correct
            hist.append(0.85, True)
            hist.append(0.85, False)

        curve = update_calibration_curve(hist.all(), n_bins=4)

        # Calibrate a high-confidence prediction
        result_high = calibrate(0.85, curve, temperature=1.0)
        assert result_high.calibrated_confidence > 0.5

        # Calibrate a low-confidence prediction
        result_low = calibrate(0.15, curve, temperature=1.0)
        assert result_low.calibrated_confidence < 0.65
