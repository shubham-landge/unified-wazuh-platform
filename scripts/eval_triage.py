#!/usr/bin/env python3
"""A/B Triage Evaluation Harness.

Runs candidate LLM configurations (model × prompt) over a labeled alert dataset
and computes accuracy metrics. Gates model swaps: new model must not regress on
false-negative rate vs. current baseline.

Usage:
    python scripts/eval_triage.py [--dataset PATH] [--output PATH] [--model MODEL]

Metrics computed:
  - verdict_accuracy      : fraction of correct verdicts
  - fn_rate               : false-negative rate (missed threats — highest weight)
  - fp_rate               : false-positive rate (wasted analyst time)
  - severity_agreement    : fraction of matching severity classifications
  - mitre_precision       : fraction of predicted MITRE techniques that are correct
  - mitre_recall          : fraction of true MITRE techniques that were predicted
  - confidence_brier      : Brier score for confidence calibration (lower = better)
  - json_validity         : fraction of responses that parsed as valid JSON
  - latency_p50_ms        : median latency in milliseconds
  - latency_p95_ms        : 95th percentile latency

Promotion gate (configurable via --fn-budget and --fp-margin):
  - fn_rate <= baseline_fn_rate (never regress on missed threats)
  - fp_rate <= baseline_fp_rate + FP_MARGIN (FP allowed to slightly worsen)
  - latency_p95_ms <= MAX_LATENCY_MS
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Default promotion gate parameters
DEFAULT_FP_MARGIN = 0.05        # FP rate can worsen by at most 5%
DEFAULT_MAX_LATENCY_MS = 45000  # 45 seconds p95


@dataclass
class EvalSample:
    """A single labeled evaluation sample."""
    alert_id: str
    alert_data: dict
    ground_truth: dict  # {verdict, severity, is_true_positive, mitre_techniques}

    @property
    def is_true_positive(self) -> bool:
        return bool(self.ground_truth.get("is_true_positive", True))

    @property
    def true_verdict(self) -> str:
        return self.ground_truth.get("verdict", "benign" if not self.is_true_positive else "malicious")

    @property
    def true_severity(self) -> str:
        return self.ground_truth.get("severity", "medium")

    @property
    def true_mitre(self) -> set[str]:
        techniques = self.ground_truth.get("mitre_techniques", [])
        if isinstance(techniques, str):
            techniques = [t.strip() for t in techniques.split(",")]
        return set(techniques)


@dataclass
class EvalResult:
    """Results from evaluating one sample."""
    sample_id: str
    predicted_verdict: str
    predicted_severity: str
    predicted_mitre: set[str]
    predicted_confidence: float
    latency_ms: float
    json_valid: bool
    raw_response: str
    error: Optional[str] = None
    result_data: dict = field(default_factory=dict)


@dataclass
class EvalMetrics:
    """Aggregated metrics across all samples."""
    model: str
    total: int = 0
    correct_verdicts: int = 0
    false_negatives: int = 0   # missed threats (predicted benign, actually malicious)
    false_positives: int = 0   # false alarms (predicted malicious, actually benign)
    true_positive_total: int = 0  # total true-positive samples in the dataset
    true_negative_total: int = 0  # total benign samples in the dataset
    severity_matches: int = 0
    severity_within_one: int = 0
    mitre_tp: float = 0.0      # for precision/recall
    mitre_pred: float = 0.0
    mitre_true: float = 0.0
    brier_sum: float = 0.0
    json_valid: int = 0
    latencies: list[float] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def verdict_accuracy(self) -> float:
        return self.correct_verdicts / max(self.total, 1)

    @property
    def fn_rate(self) -> float:
        return self.false_negatives / max(self.true_positive_total, 1)

    @property
    def fp_rate(self) -> float:
        return self.false_positives / max(self.true_negative_total, 1)

    @property
    def severity_agreement(self) -> float:
        return self.severity_matches / max(self.total, 1)

    @property
    def severity_within_one_band(self) -> float:
        return self.severity_within_one / max(self.total, 1)

    @property
    def mitre_precision(self) -> float:
        return self.mitre_tp / max(self.mitre_pred, 1)

    @property
    def mitre_recall(self) -> float:
        return self.mitre_tp / max(self.mitre_true, 1)

    @property
    def confidence_brier(self) -> float:
        return self.brier_sum / max(self.total, 1)

    @property
    def json_validity(self) -> float:
        return self.json_valid / max(self.total, 1)

    @property
    def latency_p50_ms(self) -> float:
        return statistics.median(self.latencies) if self.latencies else 0.0

    @property
    def latency_p95_ms(self) -> float:
        if not self.latencies:
            return 0.0
        sorted_l = sorted(self.latencies)
        idx = int(len(sorted_l) * 0.95)
        return sorted_l[min(idx, len(sorted_l) - 1)]

    def summary(self) -> dict:
        return {
            "model": self.model,
            "total_samples": self.total,
            "verdict_accuracy": round(self.verdict_accuracy, 4),
            "fn_rate": round(self.fn_rate, 4),
            "fp_rate": round(self.fp_rate, 4),
            "severity_agreement": round(self.severity_agreement, 4),
            "severity_within_one_band": round(self.severity_within_one_band, 4),
            "mitre_precision": round(self.mitre_precision, 4),
            "mitre_recall": round(self.mitre_recall, 4),
            "confidence_brier": round(self.confidence_brier, 4),
            "json_validity": round(self.json_validity, 4),
            "latency_p50_ms": round(self.latency_p50_ms, 1),
            "latency_p95_ms": round(self.latency_p95_ms, 1),
            "errors": len(self.errors),
        }


@dataclass
class EvalSummary:
    """Summary metrics for a candidate model evaluation."""
    model: str
    total_samples: int
    verdict_accuracy: float
    fn_rate: float
    fp_rate: float
    severity_agreement: float
    severity_within_one_band: float
    mitre_precision: float
    mitre_recall: float
    confidence_brier: float
    json_validity: float
    latency_p50_ms: float
    latency_p95_ms: float
    errors: int


# Severity band ordering for within-one-band computation
_SEVERITY_BANDS = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _within_one_band(predicted: str, true: str) -> bool:
    """Check if predicted severity is within one band of true severity."""
    p = _SEVERITY_BANDS.get(predicted.lower())
    t = _SEVERITY_BANDS.get(true.lower())
    if p is None or t is None:
        return False
    return abs(p - t) <= 1


def load_dataset(dataset_path: str) -> list[EvalSample]:
    """Load labeled evaluation samples from a JSONL file."""
    path = Path(dataset_path)
    if not path.exists():
        logger.warning("Dataset not found: %s — generating synthetic samples", dataset_path)
        return _generate_synthetic_samples()

    samples = []
    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                data = json.loads(line)
                samples.append(EvalSample(
                    alert_id=data.get("alert_id", f"sample_{line_num}"),
                    alert_data=data.get("alert", {}),
                    ground_truth=data.get("ground_truth", {}),
                ))
            except Exception as exc:
                logger.warning("Line %d parse error: %s", line_num, exc)
    logger.info("Loaded %d evaluation samples from %s", len(samples), path)
    return samples


def _generate_synthetic_samples() -> list[EvalSample]:
    """Generate synthetic samples for initial baseline testing."""
    import uuid
    samples = []

    true_positives = [
        {
            "rule_description": "Brute-force SSH login attempt from 1.2.3.4",
            "rule_level": 10, "rule_id": 5763, "source_ip": "1.2.3.4",
            "mitre_technique": "T1110", "rule_groups": "authentication_failures",
        },
        {
            "rule_description": "Possible web attack detected: SQL injection",
            "rule_level": 12, "rule_id": 31101, "source_ip": "5.6.7.8",
            "mitre_technique": "T1190", "rule_groups": "web,attack",
        },
        {
            "rule_description": "Privilege escalation via sudo",
            "rule_level": 11, "rule_id": 5501, "source_ip": "10.0.1.5",
            "mitre_technique": "T1548.003", "rule_groups": "syslog",
        },
    ]

    false_positives = [
        {
            "rule_description": "Login successful after multiple attempts",
            "rule_level": 7, "rule_id": 2502, "source_ip": "192.168.1.100",
            "mitre_technique": "T1078", "rule_groups": "authentication_success",
        },
        {
            "rule_description": "Vulnerability scan from authorized scanner",
            "rule_level": 7, "rule_id": 40101, "source_ip": "10.0.0.5",
            "mitre_technique": "", "rule_groups": "network,scan",
        },
    ]

    for alert_data in true_positives:
        samples.append(EvalSample(
            alert_id=str(uuid.uuid4())[:8],
            alert_data=alert_data,
            ground_truth={
                "verdict": "malicious",
                "severity": "high",
                "is_true_positive": True,
                "mitre_techniques": [alert_data.get("mitre_technique", "")],
            },
        ))

    for alert_data in false_positives:
        samples.append(EvalSample(
            alert_id=str(uuid.uuid4())[:8],
            alert_data=alert_data,
            ground_truth={
                "verdict": "benign",
                "severity": "low",
                "is_true_positive": False,
                "mitre_techniques": [],
            },
        ))

    logger.info("Generated %d synthetic evaluation samples", len(samples))
    return samples


async def evaluate_sample(
    sample: EvalSample,
    provider,
    system_prompt: str,
) -> EvalResult:
    """Run a single sample through the LLM and return structured result."""
    user_prompt = f"""Analyze this security alert and provide a triage verdict.

Alert data:
{json.dumps(sample.alert_data, indent=2)}

Respond with valid JSON only:
{{"verdict": "malicious|benign|suspicious", "severity": "critical|high|medium|low", "confidence": 0.0-1.0, "summary": "...", "mitre_techniques": ["T1234"]}}"""

    start = time.perf_counter()
    try:
        result = await provider.analyze(system_prompt=system_prompt, user_prompt=user_prompt)
        latency_ms = (time.perf_counter() - start) * 1000

        raw = result.get("raw_response", "") or result.get("verdict", "") or str(result)
        json_valid = False
        parsed = {}

        # Try to extract JSON
        try:
            if "{" in raw:
                json_str = raw[raw.index("{"):raw.rindex("}") + 1]
                parsed = json.loads(json_str)
                json_valid = True
        except Exception:
            pass

        return EvalResult(
            sample_id=sample.alert_id,
            predicted_verdict=parsed.get("verdict", "unknown"),
            predicted_severity=parsed.get("severity", "unknown"),
            predicted_mitre=set(parsed.get("mitre_techniques", [])),
            predicted_confidence=float(parsed.get("confidence", 0.5)),
            latency_ms=latency_ms,
            json_valid=json_valid,
            raw_response=raw[:500],
        )
    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        return EvalResult(
            sample_id=sample.alert_id,
            predicted_verdict="unknown",
            predicted_severity="unknown",
            predicted_mitre=set(),
            predicted_confidence=0.5,
            latency_ms=latency_ms,
            json_valid=False,
            raw_response="",
            error=str(exc),
        )


def accumulate_metrics(metrics: EvalMetrics, sample: EvalSample, result: EvalResult):
    """Update running metrics from a single sample result."""
    metrics.total += 1
    metrics.latencies.append(result.latency_ms)

    if result.json_valid:
        metrics.json_valid += 1

    if result.error:
        metrics.errors.append(result.error)

    # Track true-positive and true-negative totals for rate denominators
    if sample.is_true_positive:
        metrics.true_positive_total += 1
    else:
        metrics.true_negative_total += 1

    # Verdict accuracy
    pred = result.predicted_verdict.lower()
    true = sample.true_verdict.lower()

    if pred == true:
        metrics.correct_verdicts += 1
    elif sample.is_true_positive and pred in ("benign", "unknown"):
        metrics.false_negatives += 1  # missed a real threat
    elif not sample.is_true_positive and pred in ("malicious", "suspicious"):
        metrics.false_positives += 1

    # Severity — exact match
    if result.predicted_severity.lower() == sample.true_severity.lower():
        metrics.severity_matches += 1

    # Severity — within one band
    if _within_one_band(result.predicted_severity, sample.true_severity):
        metrics.severity_within_one += 1

    # MITRE precision/recall
    true_mitre = sample.true_mitre
    pred_mitre = result.predicted_mitre
    if true_mitre:
        tp = len(true_mitre & pred_mitre)
        metrics.mitre_tp += tp
        metrics.mitre_pred += len(pred_mitre)
        metrics.mitre_true += len(true_mitre)

    # Brier score: (confidence - outcome)^2 where outcome=1 for true_positive
    outcome = 1.0 if sample.is_true_positive else 0.0
    # Map confidence to P(malicious)
    if pred in ("benign",):
        p_malicious = 1.0 - result.predicted_confidence
    else:
        p_malicious = result.predicted_confidence
    metrics.brier_sum += (p_malicious - outcome) ** 2


def check_promotion_gate(
    candidate: EvalMetrics,
    baseline: Optional[EvalMetrics],
    fp_margin: float = DEFAULT_FP_MARGIN,
    max_latency_ms: float = DEFAULT_MAX_LATENCY_MS,
) -> tuple[bool, list[str]]:
    """Return (passes_gate, reasons)."""
    issues = []

    if baseline:
        if candidate.fn_rate > baseline.fn_rate + 0.001:
            issues.append(
                f"FN rate regressed: {candidate.fn_rate:.3f} > {baseline.fn_rate:.3f} (baseline)"
            )
        if candidate.fp_rate > baseline.fp_rate + fp_margin:
            issues.append(
                f"FP rate degraded beyond margin: {candidate.fp_rate:.3f} > {baseline.fp_rate:.3f}+{fp_margin}"
            )

    if candidate.latency_p95_ms > max_latency_ms:
        issues.append(f"p95 latency {candidate.latency_p95_ms:.0f}ms > {max_latency_ms:.0f}ms limit")

    if candidate.json_validity < 0.9:
        issues.append(f"JSON validity {candidate.json_validity:.2%} < 90% minimum")

    return len(issues) == 0, issues


def compute_metrics(
    results: list[tuple[EvalSample, EvalResult]],
    model_name: str = "candidate",
) -> EvalSummary:
    """Aggregate metrics from a list of (sample, result) pairs.

    Pure function: no side effects, works on any collection of results.
    """
    metrics = EvalMetrics(model=model_name)
    for sample, result in results:
        accumulate_metrics(metrics, sample, result)
    s = metrics.summary()
    return EvalSummary(
        model=s["model"],
        total_samples=s["total_samples"],
        verdict_accuracy=s["verdict_accuracy"],
        fn_rate=s["fn_rate"],
        fp_rate=s["fp_rate"],
        severity_agreement=s["severity_agreement"],
        severity_within_one_band=s["severity_within_one_band"],
        mitre_precision=s["mitre_precision"],
        mitre_recall=s["mitre_recall"],
        confidence_brier=s["confidence_brier"],
        json_validity=s["json_validity"],
        latency_p50_ms=s["latency_p50_ms"],
        latency_p95_ms=s["latency_p95_ms"],
        errors=s["errors"],
    )


FP_MARGIN = DEFAULT_FP_MARGIN


def promotion_gate(results: EvalSummary, baseline_fn: float, baseline_fp: float) -> bool:
    """Return True if candidate can replace baseline.

    Gate rules:
      - fn_rate <= baseline_fn  (never regress on missed threats)
      - fp_rate <= baseline_fp + FP_MARGIN  (FP may slightly worsen)
    """
    if results.fn_rate > baseline_fn:
        logger.warning(
            "FN gate FAILED: candidate fn=%.4f > baseline fn=%.4f",
            results.fn_rate, baseline_fn,
        )
        return False
    if results.fp_rate > baseline_fp + FP_MARGIN:
        logger.warning(
            "FP gate FAILED: candidate fp=%.4f > baseline fp=%.4f + margin=%.4f",
            results.fp_rate, baseline_fp, FP_MARGIN,
        )
        return False
    return True


async def run_eval(
    model_name: str,
    dataset_path: str,
    output_path: Optional[str] = None,
    system_prompt_path: Optional[str] = None,
    baseline_metrics: Optional[EvalMetrics] = None,
    fp_margin: float = DEFAULT_FP_MARGIN,
    max_latency_ms: float = DEFAULT_MAX_LATENCY_MS,
) -> EvalMetrics:
    """Run the full evaluation."""
    samples = load_dataset(dataset_path)
    if not samples:
        logger.error("No samples loaded — aborting")
        sys.exit(1)

    # Load system prompt
    if system_prompt_path and Path(system_prompt_path).exists():
        system_prompt = Path(system_prompt_path).read_text()
    else:
        system_prompt = (
            "You are NotMythos, a cybersecurity triage expert. "
            "Analyze alerts and return JSON with: verdict, severity, confidence, summary, mitre_techniques."
        )

    # Get provider
    from shared.connectors.llm_provider import OllamaProvider
    provider = OllamaProvider(model=model_name)

    metrics = EvalMetrics(model=model_name)

    logger.info("Evaluating model '%s' on %d samples...", model_name, len(samples))
    for i, sample in enumerate(samples, 1):
        result = await evaluate_sample(sample, provider, system_prompt)
        accumulate_metrics(metrics, sample, result)

        verdict_icon = "✓" if result.predicted_verdict == sample.true_verdict else "✗"
        logger.info(
            "[%d/%d] %s %s→%s (%.0fms) json=%s",
            i, len(samples), verdict_icon,
            sample.true_verdict, result.predicted_verdict,
            result.latency_ms, result.json_valid,
        )

    summary = metrics.summary()
    logger.info("\n=== EVALUATION RESULTS ===\n%s", json.dumps(summary, indent=2))

    passes, issues = check_promotion_gate(metrics, baseline_metrics, fp_margin, max_latency_ms)
    if passes:
        logger.info("✅ PROMOTION GATE PASSED — model '%s' is safe to promote", model_name)
    else:
        logger.warning("❌ PROMOTION GATE FAILED:")
        for issue in issues:
            logger.warning("   - %s", issue)

    if output_path:
        Path(output_path).mkdir(parents=True, exist_ok=True)
        out_file = Path(output_path) / f"eval_{model_name.replace('/', '_')}.json"
        with open(out_file, "w") as f:
            json.dump({"summary": summary, "promotion_gate": {"passed": passes, "issues": issues}}, f, indent=2)
        logger.info("Results written to %s", out_file)

    return metrics


def main():
    parser = argparse.ArgumentParser(description="AI SOC Triage Evaluation Harness")
    parser.add_argument("--model", default="Foundation-Sec-8B-Instruct", help="Ollama model to evaluate")
    parser.add_argument("--dataset", default="tests/fixtures/triage_eval/samples.jsonl", help="Labeled dataset path")
    parser.add_argument("--output", default="reports/eval", help="Output directory for results")
    parser.add_argument("--system-prompt", default=None, help="Path to system prompt file")
    parser.add_argument("--fp-margin", type=float, default=DEFAULT_FP_MARGIN)
    parser.add_argument("--max-latency-ms", type=float, default=DEFAULT_MAX_LATENCY_MS)
    parser.add_argument("--baseline-fn", type=float, default=None,
                        help="Baseline false-negative rate for promotion gate")
    parser.add_argument("--baseline-fp", type=float, default=None,
                        help="Baseline false-positive rate for promotion gate")
    args = parser.parse_args()

    metrics = asyncio.run(run_eval(
        model_name=args.model,
        dataset_path=args.dataset,
        output_path=args.output,
        system_prompt_path=args.system_prompt,
        fp_margin=args.fp_margin,
        max_latency_ms=args.max_latency_ms,
    ))

    # Run promotion gate if baselines are provided
    if args.baseline_fn is not None or args.baseline_fp is not None:
        s = metrics.summary()
        summary = EvalSummary(
            model=s["model"],
            total_samples=s["total_samples"],
            verdict_accuracy=s["verdict_accuracy"],
            fn_rate=s["fn_rate"],
            fp_rate=s["fp_rate"],
            severity_agreement=s["severity_agreement"],
            severity_within_one_band=s["severity_within_one_band"],
            mitre_precision=s["mitre_precision"],
            mitre_recall=s["mitre_recall"],
            confidence_brier=s["confidence_brier"],
            json_validity=s["json_validity"],
            latency_p50_ms=s["latency_p50_ms"],
            latency_p95_ms=s["latency_p95_ms"],
            errors=s["errors"],
        )
        baseline_fn = args.baseline_fn if args.baseline_fn is not None else 1.0
        baseline_fp = args.baseline_fp if args.baseline_fp is not None else 1.0
        passed = promotion_gate(summary, baseline_fn, baseline_fp)
        if passed:
            logger.info("✅ PROMOTION GATE PASSED — model '%s' can replace baseline", args.model)
        else:
            logger.warning("❌ PROMOTION GATE BLOCKED — model '%s' fails gate", args.model)


if __name__ == "__main__":
    main()
