"""Confidence calibration and decision fusion for the enrichment engine.

Provides:
  - Platt-style temperature scaling for raw confidence scores.
  - Non-parametric bin-based calibration curve (lightweight isotonic approximation).
  - Weighted majority voting for ensemble decision fusion.
  - In-memory ring buffer (ConfidenceHistory) for accumulating calibration data.

All functions are pure and testable — no DB, no Redis, no ML dependencies.
Fail-open: if calibration data is insufficient, raw confidence is returned unchanged.
"""
from __future__ import annotations

import logging
import math
from collections import deque
from dataclasses import dataclass
from typing import Optional

from shared.config import settings

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
_MAX_HISTORY_LEN = 10_000
_MIN_SAMPLES_FOR_CALIBRATION = 20


# ── Dataclasses ──────────────────────────────────────────────────────────────


@dataclass
class CalibratedConfidence:
    """Result of confidence calibration."""
    raw_confidence: float
    calibrated_confidence: float
    temperature: float
    bin_index: int


# ── Temperature scaling ──────────────────────────────────────────────────────


def _apply_temperature(raw_confidence: float, temperature: float) -> float:
    """Apply Platt-style temperature scaling to a raw confidence value.

    T=1.0 → no change; T<1 → sharper (more extreme); T>1 → softer (less extreme).

    Handles edge-values (0.0, 1.0) gracefully via clamping.
    """
    # Clamp to avoid log(0) / log(inf)
    c = max(0.001, min(0.999, raw_confidence))
    logit = math.log(c / (1.0 - c))
    calibrated = 1.0 / (1.0 + math.exp(-logit / temperature))
    return calibrated


# ── Calibration curve ────────────────────────────────────────────────────────


def update_calibration_curve(
    history: list[tuple[float, bool]], n_bins: int = 10
) -> dict[int, tuple[float, float]]:
    """Build a calibration curve from (confidence, outcome) pairs.

    Uses equal-frequency histogram binning — a lightweight non-parametric
    approximation of isotonic regression with no heavy ML dependencies.

    Args:
        history: List of (confidence, was_correct) pairs.
        n_bins: Number of histogram bins (default 10).

    Returns:
        Dict mapping bin_index → (bin_center_confidence, calibrated_accuracy).
        Empty dict if history has fewer than _MIN_SAMPLES_FOR_CALIBRATION entries.
    """
    if len(history) < _MIN_SAMPLES_FOR_CALIBRATION:
        return {}

    # Sort by confidence
    sorted_history = sorted(history, key=lambda x: x[0])

    n_bins = max(2, min(n_bins, len(sorted_history) // 3))
    bin_size = len(sorted_history) / n_bins

    curve: dict[int, tuple[float, float]] = {}
    for i in range(n_bins):
        start = int(round(i * bin_size))
        end = int(round((i + 1) * bin_size))
        bucket = sorted_history[start:end]

        if not bucket:
            continue

        bin_center = sum(p[0] for p in bucket) / len(bucket)
        accuracy = sum(1 for _, correct in bucket if correct) / len(bucket)
        curve[i] = (bin_center, accuracy)

    return curve


def calibrate(
    raw_confidence: float,
    calibration_curve: dict[int, tuple[float, float]],
    temperature: Optional[float] = None,
) -> CalibratedConfidence:
    """Apply temperature scaling and bin-based calibration.

    Steps:
      1. Apply temperature scaling (if temperature provided).
      2. Find the nearest calibration bin(s) and interpolate.
      3. If no calibration curve is available, return the raw/temperature-scaled
         value unchanged (fail-open).

    Args:
        raw_confidence: Raw confidence in [0, 1].
        calibration_curve: Output of update_calibration_curve().
        temperature: Temperature parameter for Platt scaling (None = use settings default).

    Returns:
        CalibratedConfidence with all metadata populated.
    """
    # Read temperature from settings if not provided
    if temperature is None:
        temperature = float(getattr(settings, "calibration_temperature", 1.0))

    # Temperature scaling
    scaled = _apply_temperature(raw_confidence, temperature)

    # If no calibration curve, return temperature-scaled value as-is
    if not calibration_curve:
        return CalibratedConfidence(
            raw_confidence=raw_confidence,
            calibrated_confidence=scaled,
            temperature=temperature,
            bin_index=-1,
        )

    # Find the two nearest bins (left and right) for linear interpolation
    bins_sorted = sorted(calibration_curve.items(), key=lambda x: x[1][0])  # sort by bin_center
    bin_centers = [(idx, center, acc) for idx, (center, acc) in bins_sorted]

    # Locate surrounding bins for the scaled confidence
    left_idx = -1
    right_idx = -1
    for i, (idx, center, _acc) in enumerate(bin_centers):
        if center <= scaled:
            left_idx = i
        if center >= scaled and right_idx == -1:
            right_idx = i

    # Handle edge cases
    if left_idx == -1:
        # scaled confidence is below all bins → use first bin
        _, _, acc = bin_centers[0]
        return CalibratedConfidence(
            raw_confidence=raw_confidence,
            calibrated_confidence=acc,
            temperature=temperature,
            bin_index=bin_centers[0][0],
        )
    if right_idx == -1:
        # scaled confidence is above all bins → use last bin
        _, _, acc = bin_centers[-1]
        return CalibratedConfidence(
            raw_confidence=raw_confidence,
            calibrated_confidence=acc,
            temperature=temperature,
            bin_index=bin_centers[-1][0],
        )

    # Interpolate between left and right bins
    if left_idx == right_idx:
        _, _, acc = bin_centers[left_idx]
        calibrated_val = acc
        bin_idx = bin_centers[left_idx][0]
    else:
        _, c_left, a_left = bin_centers[left_idx]
        _, c_right, a_right = bin_centers[right_idx]
        if c_right > c_left:
            frac = (scaled - c_left) / (c_right - c_left)
            calibrated_val = a_left + frac * (a_right - a_left)
        else:
            calibrated_val = (a_left + a_right) / 2.0
        bin_idx = bin_centers[left_idx][0]

    return CalibratedConfidence(
        raw_confidence=raw_confidence,
        calibrated_confidence=calibrated_val,
        temperature=temperature,
        bin_index=bin_idx,
    )


# ── Decision fusion ──────────────────────────────────────────────────────────


def fuse_decisions(
    decisions: list[tuple[str, float]],
    weights: Optional[list[float]] = None,
) -> tuple[str, float]:
    """Weighted majority voting for ensemble decisions.

    Args:
        decisions: List of (label, confidence) pairs.
        weights: Optional per-vote weight (defaults to uniform if None).

    Returns:
        (winning_label, fused_confidence) where fused_confidence is the
        weight-normalized score of the winning label in [0, 1].

    Raises:
        ValueError: if decisions is empty.
    """
    if not decisions:
        raise ValueError("fuse_decisions: decisions list must not be empty")

    n = len(decisions)
    if weights is None:
        weights = [1.0] * n
    elif len(weights) != n:
        raise ValueError(
            f"fuse_decisions: expected {n} weights, got {len(weights)}"
        )

    # Aggregate weighted votes per unique label
    votes: dict[str, float] = {}
    for (label, conf), w in zip(decisions, weights):
        votes[label] = votes.get(label, 0.0) + conf * w

    if not votes:
        raise ValueError("fuse_decisions: no valid votes accumulated")

    total_weight = sum(weights)
    winner = max(votes, key=votes.__getitem__)  # type: ignore[arg-type]

    # Normalize winning score to [0, 1]
    if total_weight > 0:
        fused_conf = votes[winner] / total_weight
    else:
        fused_conf = 0.0

    # Clamp
    fused_conf = max(0.0, min(1.0, fused_conf))
    return winner, fused_conf


# ── Confidence history ring buffer ───────────────────────────────────────────


class ConfidenceHistory:
    """In-memory ring buffer for accumulating calibration data.

    Stores (confidence, outcome) pairs up to _MAX_HISTORY_LEN entries.
    Thread-safe for append/read but not for concurrent iteration.

    Usage:
        hist = ConfidenceHistory()
        hist.append(0.85, True)
        curve = update_calibration_curve(hist.all())
    """

    def __init__(self, maxlen: int = _MAX_HISTORY_LEN):
        self._buffer: deque[tuple[float, bool]] = deque(maxlen=maxlen)
        self._maxlen = maxlen

    def append(self, confidence: float, outcome: bool) -> None:
        """Append a (confidence, was_correct) pair. Oldest is dropped if full."""
        self._buffer.append((confidence, outcome))

    def all(self) -> list[tuple[float, bool]]:
        """Return a copy of all entries as a list."""
        return list(self._buffer)

    def __len__(self) -> int:
        return len(self._buffer)

    def clear(self) -> None:
        """Remove all entries."""
        self._buffer.clear()

    @property
    def is_ready_for_calibration(self) -> bool:
        """Check if enough data exists to build a calibration curve."""
        return len(self._buffer) >= _MIN_SAMPLES_FOR_CALIBRATION
