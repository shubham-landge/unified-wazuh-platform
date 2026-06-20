"""Shared enrichment package — pre-LLM risk scoring and decision gate.

Architecture:
  pipeline.py       — parallel fan-out, timeout-bounded, fail-open
  geoip.py          — MaxMind GeoLite2 City+ASN (offline, microsecond lookups)
  ti.py             — Threat intelligence IOC lookup from database
  asset.py          — Asset criticality lookup from assets table
  user.py           — User risk factor assessment (privileged, service acct, dormant)
  vuln_correlate.py — exploit alert to open CVE on target host
  watchlists.py     — tenant-scoped allow/block/crown-jewel lists
  risk_score.py     — deterministic 0-100 additive score engine
  ueba_history.py   — historical UEBA anomaly lookup for entity context
  decision.py       — L0-L4 gate: suppress / auto-close / triage / escalate / critical
  calibration.py    — confidence calibration + decision fusion
  auto_close.py     — audited auto-close pipeline with shadow mode
  semantic_cache.py — embedding-similarity verdict cache
  fingerprint.py    — deterministic SHA-256 fingerprint for meta-alert grouping
  containment_gate.py — automated containment decision gate
  decision_fusion.py  — ensemble decision fusion
"""

# Core pipeline entry-point
from shared.enrichment.pipeline import run, enrich_alert  # noqa: F401

# Enricher modules
from shared.enrichment import geoip       # noqa: F401
from shared.enrichment import ti          # noqa: F401
from shared.enrichment import asset       # noqa: F401
from shared.enrichment import user        # noqa: F401
from shared.enrichment import vuln_correlate  # noqa: F401
from shared.enrichment import watchlists  # noqa: F401
from shared.enrichment import ueba_history  # noqa: F401

# Scoring and decision
from shared.enrichment.risk_score import EnrichmentContext, compute, compute_risk_score  # noqa: F401
from shared.enrichment.decision import decide, Decision, DecisionLevel  # noqa: F401
from shared.enrichment.auto_close import should_auto_close, execute_auto_close  # noqa: F401
