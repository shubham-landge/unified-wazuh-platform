# Issues

## Enrichment Package Build — COMPLETED

**Summary:** Built the shared/enrichment/ package by extracting inline enrichers from `pipeline.py` into dedicated modules. Four new enricher modules were created to complete the enrichment chain: TI, asset, user, and UEBA history.

**Files created:**
- `shared/enrichment/ti.py` — Threat intelligence IOC lookup from `threat_intel_iocs` table. Returns (is_known_bad, confidence, is_kev). Fail-open on DB error.
- `shared/enrichment/asset.py` — Asset criticality lookup from `assets` table by `agent_id`. Detects crown-jewel assets (criticality ≥ 9 or label override).
- `shared/enrichment/user.py` — User risk factor assessment. Checks privileged username patterns (root, admin, DomainAdmin, etc.), service account patterns (svc-*, SYSTEM), and dormant-reactivation detection via alert history.
- `shared/enrichment/ueba_history.py` — Historical UEBA anomaly lookup. Queries `ueba_anomalies` table for entity history (agent, user, IP) over a configurable look-back window.

**Files modified:**
- `shared/enrichment/__init__.py` — Added exports for ti, asset, user, ueba_history modules.
- `shared/enrichment/pipeline.py` — Replaced inline `_run_ti` and added `_run_asset`, `_run_user`, and `_run_ueba_history` enrichers. All seven enrichers now fan out in parallel with individual timeouts.
- `tests/test_enrichment.py` — Added TestTIEnricher, TestAssetEnricher, TestUserEnricher, TestUebaHistory, and TestFullPipelineWireup test classes (31 new tests). Total: 65 tests, all passing.

**Pipeline enricher fan-out (7 parallel, fail-open):**
1. `_run_geo` (0.5s timeout) — GeoIP lookup + impossible travel
2. `_run_ti` (2.0s) — DB IOC lookup via `ti.lookup()`
3. `_run_asset` (1.0s) — DB asset criticality via `asset.get_asset_criticality()`
4. `_run_user` (1.0s) — DB user risk factors via `user.get_user_risk_factors()`
5. `_run_vuln` (2.0s) — DB vulnerability correlation via `vuln_correlate.correlate()`
6. `_run_ueba` (2.0s) — Real-time UEBA z-score via `detector.process_alert()`
7. `_run_ueba_history` (2.0s) — DB historical anomaly lookup via `ueba_history.get_entity_history()`

**Verification:** 65/65 tests pass, zero failures, zero errors.

**Root cause:** `triage_worker.py` was calling `analyze_alert(session, alert)` but the UEBA detector module (`shared/ueba/detector.py`) exports `process_alert(session, alert, tenant_id)`. The name mismatch caused an `ImportError` on the lazy import at runtime.

**Fix applied:** Commit `7a9efb3` renamed the call to `process_alert(session, alert, str(alert.tenant_id) if alert.tenant_id else None)` at line 482-483 of `services/worker/app/triage_worker.py`.

**Verification:** Added `tests/test_ueba_import.py` which:
- Validates `process_alert` is importable from `shared.ueba.detector`
- Validates `analyze_alert` **no longer exists** in the module
- Validates the function signature matches the calling convention `(session, alert, tenant_id)`

---

## Orchestrator Enrichment Refactoring — COMPLETED

**Summary:** Wired the `shared/orchestrator/enrichment.py` → `shared/enrichment/` delegation chain. The orchestrator's `enrich_incident()` already imported `enrich_alert` from `shared.enrichment.pipeline` via the `from shared.enrichment.pipeline import enrich_alert` import (line 23), but the EvidencePack aggregation code at lines 180-194 expected `EnrichmentContext` objects to carry `.ti`, `.asset`, `.user`, `.ueba` list attributes — which did not exist on the dataclass. This was a gap between the pipeline's scalar output (designed for scoring) and the orchestrator's need for structured dicts (designed for EvidencePack aggregation).

**Root cause:** `EnrichmentContext` had scalar fields only (`ti_is_known_bad`, `asset_criticality`, `user_is_privileged`, `ueba_zscore`) — sufficient for `compute()` and `decide()` but insufficient for the orchestrator's EvidencePack which requires per-alert dict entries aggregated into lists and deduplicated across alerts within an incident.

**Fix applied (3 files):**

1. **`shared/enrichment/risk_score.py`** (line 17-59) — Added four raw result list fields to the `EnrichmentContext` dataclass:
   - `ti: list[dict]` — IOC lookup results per alert
   - `asset: list[dict]` — asset criticality results per alert
   - `user: list[dict]` — user risk factor results per alert
   - `ueba: list[dict]` — UEBA anomaly results per alert

2. **`shared/enrichment/pipeline.py`** — Each enricher now populates both scalar signals AND raw result lists:
   - `_run_ti`: appends `{"ioc", "is_known_bad", "confidence", "is_kev"}` to `ctx.ti`
   - `_run_asset`: appends `{"agent_id", "criticality", "is_crown_jewel"}` to `ctx.asset`
   - `_run_user`: appends `{"user_name", "is_privileged", "is_service_acct_interactive", "is_dormant_reactivated"}` to `ctx.user`
   - `_run_ueba`: appends per-anomaly `{"subject_type", "subject_id", "z_score", "anomaly_type"}` to `ctx.ueba`
   - `_run_ueba_history`: extends `ctx.ueba` with historical anomaly dicts

3. **`tests/test_orchestrator_enrichment.py`** — New test file with 27 tests across 7 test classes:
   - `TestEvidencePack` (2): constructor defaults, to_dict() serialization
   - `TestDeduplicateDicts` (5): dedup by key, first-occurrence preservation, empty/single/tuple-key
   - `TestEnrichIncidentDelegation` (6): empty alerts, TI/asset/user/UEBA aggregation, incident-level enrichers
   - `TestEnrichIncidentErrors` (4): partial failure, all-raise, few-shot failure, related-incidents failure
   - `TestEnrichIncidentDedup` (4): TI IOC dedup, asset agent-id dedup, user email dedup, UEBA subject dedup
   - `TestImportPaths` (5): orchestrator imports from shared package, pipeline backward compat, context raw field shape
   - `TestOrchestratorEnrichmentIntegration` (1): end-to-end flow with multiple enriched alerts

**Verification:** 98/98 tests pass (65 existing + 27 new + 6 integration). Zero failures, zero errors. Pre-existing warnings (6 RuntimeWarning for mock coroutine tracing) unchanged.
