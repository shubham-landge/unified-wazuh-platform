"""Shared enrichment package — pre-LLM risk scoring and decision gate.

Architecture:
  pipeline.py   — parallel fan-out, timeout-bounded, fail-open
  geoip.py      — MaxMind GeoLite2 City+ASN (offline, µs lookups)
  vuln_correlate.py — exploit alert ↔ open CVE on target host
  watchlists.py — tenant-scoped allow/block/crown-jewel lists
  risk_score.py — deterministic 0-100 additive score engine
  decision.py   — L0-L4 gate: suppress / auto-close / triage / escalate / critical
  calibration.py — confidence calibration + decision fusion
  auto_close.py — audited auto-close pipeline with shadow mode
  semantic_cache.py — embedding-similarity verdict cache
"""
