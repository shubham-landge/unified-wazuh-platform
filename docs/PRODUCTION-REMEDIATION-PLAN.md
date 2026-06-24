# Production Remediation Plan — make every feature actually work

**Audience:** OpenCode (build) · **Reviewer:** Claude. **Validated against the codebase 2026-06-21.**
The audit handed in is ~90% accurate (confirmed below). Fix **root-cause patterns**, not symptoms.

## 0. The two cross-cutting truths (read first)

- **A) Migrations must be APPLIED on the VM, not just committed.** `005_entities.sql` /
  `006_case_incident_fk.sql` exist in the repo (commit `5af5371`) but are useless until run on
  Manager-3's Postgres. The whole `stitch_incident` failure is this. **Make the deploy apply all
  `database/migrations/*.sql` idempotently on startup** (or a one-shot `scripts/apply_migrations.sh`)
  — and verify with `SELECT to_regclass('public.entities');` returning non-NULL.
- **B) Most "empty page" bugs share ONE pattern: the table is never populated.** Assets, audit_log,
  TenantUsage, playbook_executions — UI + API + schema all exist, but **no worker writes data**.
  These are *missing-producer* bugs, fixed by building the producer, not touching the UI.

---

## Phase P0 — Triage actually produces verdicts (the #1 user-visible failure)

**Symptom:** "Triage Pending" forever / everything 50%. **Confirmed root cause (compound):**

1. **Shadow-mode L1 leaves alerts with no verdict.** `shared/enrichment/auto_close.py:99-114`: in
   `AUTOMATION_MODE=shadow` (the default), `execute_auto_close` logs + returns but **does NOT change
   alert status and does NOT run the LLM** → the worker `return`s → alert stays `open`, no
   `AiTriageResult` → UI shows "pending" indefinitely. Same for **L0 suppress** (no verdict by design).
   With the deterministic gate shedding most alerts, the dashboard looks dead.
   **Fix:** in shadow mode, L0/L1 must still produce a *visible outcome*: either (a) run the LLM
   anyway and record the verdict while logging "would-suppress/close" (preferred — needed to measure
   agreement), or (b) write a distinct status (`shadow_suppressed`/`shadow_auto_closed`) + a synthetic
   `AiTriageResult` so the UI shows a result, not "pending". Add a config `SHADOW_STILL_TRIAGES=true`.
2. **Confidence defaults to 0.5** in `triage_worker.py:~408`, `triage.py:40`, `decision_fusion.py:55`
   when no real verdict exists. Once #1 is fixed these stop firing; also make the UI render
   "awaiting analysis" vs a fake 50%.
3. **Verify the VM runtime** (not a code bug, but blocks everything): `docker logs soc-worker` for
   the triage loop; `ollama ps` shows the models loaded; `OLLAMA_BASE_URL` reachable from the worker
   container; `TRIAGE_ENABLED=true`; Redis `LLEN triage_queue` (is the worker consuming?). The
   `llm_max_concurrency=1` semaphore is fine — confirm it's not stuck on a 230s call (that's
   throughput, not deadlock).

**Acceptance:** a freshly polled alert reaches a non-pending state (verdict OR explicit suppressed/
auto-closed status) within one triage cycle; no alert sits "pending" past the reaper timeout.

---

## Phase P1 — Build the missing data producers (empty pages)

Each: schema/API/UI already exist; **build the worker that fills the table**, register in
`services/worker/app/main.py`, add a test.

| # | Feature (empty) | Confirmed root cause | Build |
|---|---|---|---|
| 5 | **Assets / Agent inventory** | **No worker writes `assets`** (verified — nothing calls `get_agents()`→`assets`) | New `services/worker/app/asset_sync_worker.py`: periodically `WazuhAPIConnector.get_agents()` → upsert `assets` (agent_id, name, ip, os, status, last_seen). Register in worker main. |
| 6 | **System Audit Logs** | `middleware/audit.py` only `logger.info()` — **no DB write** (verified) | Rewrite `AuditMiddleware` to insert `AuditLog` rows (actor, method, path, status, tenant_id, ts) on state-changing requests. Keep it non-blocking (fire-and-forget task). |
| 13 | **Usage tab** | `TenantUsage` never populated; no aggregator (verified path `usage.py:80-108`) | New usage-aggregation job (cron in ARQ or a worker): roll `UsageRecord` → `TenantUsage` summaries per tenant/day. |
| 7 | **Playbooks dashboard is fake** | `playbook_worker.py` **missing** (referenced `main.py:26`, silently skipped); dashboard `main.py:1214-1243` uses a local JSON store with hardcoded "3.1s" | Build `playbook_worker.py` that consumes `playbook_queue` and runs the **real** `shared/soar/engine.py`; point the dashboard at real `SoarExecution` rows. Remove the fake JSON store. |

---

## Phase P2 — Pipeline correctness (data exists but wrong/partial)

| # | Bug | Confirmed root cause | Fix |
|---|---|---|---|
| 1 | **Vulnerabilities empty** | `vuln_ingester.py:148-158` increments `offset` but `search_vulnerabilities(size=100)` has **no `from` param** → same page re-fetched forever; `asset_id` always None | Add `from_`/offset param to `search_vulnerabilities()` (`wazuh_indexer.py:97`) and pass it in `_fetch_all`; resolve `asset_id` by joining agent_id→assets (needs P1 #5). |
| 4 | **Only ~100 alerts** | `search_alerts()` (`wazuh_indexer.py:62`) fetches a **single page** of `size=100`, no scroll/`search_after` | Add `search_after`/scroll pagination to `search_alerts`; raise/loop `max_alerts_per_poll`. Make `GET /alerts/recent` use keyset pagination (avoid OFFSET phantom reads). |
| 3 | **Alert detail N/A fields** | `poller.py:145-168` `_normalize_alert` never maps `source_port, destination_port, protocol, process_pid, file_path, event_type, event_action, log_source, principal, session_id` | Add the field mappings (read from the Wazuh `data.*`/`rule.*` JSON); backfill existing rows from `raw_alert_redacted`. |
| 11 | **ATT&CK heatmap empty** | `cases.py:573` reads **only** `AiTriageResult.mitre_mapping`; if triage didn't complete, empty | Add **fallback to `alerts.mitre_tactic`/`alerts.mitre_technique`** (poller always populates these). Union both sources. |
| 10 | **MTTR empty** | `cases.py:495-565` returns zeros if no closed cases; **endpoint ignores tenant** (`X-Tenant-ID`) | Add tenant filter via `get_tenant_id`/`require_tenant_uuid`; show "no closed cases yet" empty-state instead of silent zeros. |
| 12 | **OSINT email/domain** | `osint_worker.py:51-56` only handles **username**; email/domain call `lookup_username()` → 0 results; duplicate routes `main.py:690` & `1932` | Branch on indicator type (username/email/domain) to the right Maigret/OSINT call; remove the duplicate route. |
| 9 | **Executive report fails** | `executive_summary.html` **exists**; likely `weasyprint` not installed *in the container* (it IS in `requirements.txt==62.3`) OR a template var KeyError; bg task sets `status="failed"` | Verify `weasyprint` import inside the API/worker image (its native libs — pango/cairo — must be in the Dockerfile); add HTML-only fallback when PDF libs absent; surface the real error to the UI. |

---

## Phase P3 — Frontend / UI (no glitches, nothing dead)

| # | Bug | File | Fix |
|---|---|---|---|
| 8 | **Report download is a placeholder** | `reports.html:140` `<a href="#">` | Point to the working endpoint: `href="/api/reports/{{ rep.id }}/download"` (API already works). |
| — | **Compliance console empty** | needs seeding | Run/seed the compliance frameworks (script exists per audit); add a "seed frameworks" admin action. |
| — | **CSRF mismatch** | `main.py:258-286` middleware expects `X-CSRF-Token` **header**, forms post a hidden field | Align: either read the hidden `csrf_token` form field in the middleware, or have HTMX send the header. Pick one and apply repo-wide so no POST 403s. |

**UI glitch sweep (do this, don't assume):** drive the dashboard with the browser/preview tools and
walk every page (overview, alerts, alert-detail, cases, case-detail, vulnerabilities, assets,
playbooks, threat-intel, compliance, notifications, audit, reports, health, wazuh-environment,
coverage-map, usage, settings, OSINT, agents). For each: page returns 200, charts render (not blank
canvas), tables show data or a proper empty-state (never a spinner-forever or "N/A" grid), all
buttons have real hrefs/handlers, no JS console errors. Fix the dead `href="#"`/no-op handlers and
any chart that initializes against an empty dataset without an empty-state.

---

## Phase P4 — Security / correctness polish (from the audit + my scan)

- **Credentials:** `scripts/seed_admin.py:15-16` is `admin@company.com` / `admin123` (audit said
  "Paylessadmin" — slightly off). Change to the intended `admin@payless.com` / a strong secret
  **sourced from env**, not hardcoded; remove any hardcoded login bypass in `main.py:~1450`.
- **`python-jose==3.3.0`** has known CVEs (algorithm-confusion / DoS) — upgrade or migrate to PyJWT.
- **Tenant isolation on stats endpoints:** `cases.py` `/stats/mttr` and `/stats/mitre-heatmap`
  ignore tenant — add `require_tenant_uuid` consistently (matches the other routers).
- **`vuln_correlate.py:55`** uses `v.agent_id`; column is `asset_id` — fix (dormant/off by default,
  but wrong).
- **`asset_criticality()` stub** (`llm_router.py:62`) always returns 0 → weakens routing/risk score.
  Implement the real `assets.criticality` lookup (depends on P1 #5).
- Add **`pip-audit` + `bandit`** to CI (no automated dep/SAST scanning today).

---

## Sequencing & ownership

1. **P0 first** (triage verdicts + apply migrations on VM) — unblocks the heatmap (#11), MTTR (#10),
   and the "everything pending" perception in one stroke.
2. **P1 producers** (assets → also unblocks vuln `asset_id` + asset_criticality).
3. **P2 pipeline** correctness, **P3 UI**, **P4 polish**.
4. Each fix ships with a test; keep the suite green (currently **984 passing**). After each phase,
   rebuild the affected containers on Manager-3 and re-walk the relevant pages.
5. **Ops, in parallel:** disk is at 92% — prune images/old models before rebuilding, or builds fail.

## Acceptance (definition of "production works")

- No page shows a perpetual spinner, an all-`N/A` grid, or a dead button.
- A polled alert reaches a verdict or an explicit suppressed/auto-closed status every cycle.
- Vulnerabilities, Assets, Audit, Usage, Playbooks, Reports-download, Heatmap, MTTR all show real
  data (or a correct empty-state) for the production tenant.
- `entities` tables exist on the VM; `stitch_incident failed` log count ≈ 0; incidents group by entity.
- Tenant isolation enforced on every list/stat/detail endpoint; CSRF consistent; no hardcoded creds.
