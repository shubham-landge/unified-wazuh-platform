# Unified Wazuh SOC Platform — Structured Improvement Plan

Generated from commit review `4fd9a82..ac2df8f` and full architecture audit.
Date: 2026-06-14

---

## Commit ac2df8f Review Summary

| Change | Verdict | Notes |
|--------|---------|-------|
| Silent except → named logging | ✅ Good | All bare `except: pass` replaced with `logger.warning/debug`. Errors now surface in logs. |
| report_scheduler.py — real generation | ✅ Good | Replaced TODO stub with actual ReportGenerator calls for 5 report types. Core logic correct. |
| notify_email.py — MIME attachments | ⚠️ Partial | Attachment support added. Bug: `att['mime_type']` ignored — Content-Type hardcoded to `application/octet-stream`. |
| dashboard generate_report — use API response | ✅ Good | Was ignoring POST /reports response and fabricating fake entries. Now uses real API data. |
| .env.example — all missing vars documented | ✅ Good | 52 lines added covering RAG, metering, tiered LLM, OSINT, ticketing, API defaults. |
| audit.py — body read error logged | ✅ Good | Trivial but correct. |
| report_scheduler html_to_pdf blocking | 🔴 Bug | `html_to_pdf()` called inside async function without `run_in_executor`. Blocks the event loop. |
| report_scheduler last_run_at on failure | 🔴 Bug | `last_run_at` updated even when delivery fails. Schedule won't retry until next cron tick. |

### Bugs Introduced in ac2df8f (fix immediately)

| # | Severity | File:Line | Fix |
|---|----------|-----------|-----|
| 1 | HIGH | `shared/connectors/notify_email.py:46-49` | Replace hardcoded `application/octet-stream` with `att["mime_type"]` in `MIMEBase` constructor |
| 2 | HIGH | `services/worker/app/report_scheduler.py:120` | Wrap `html_to_pdf()` in `asyncio.get_event_loop().run_in_executor(None, generator.html_to_pdf, html)` |
| 3 | MEDIUM | `services/worker/app/report_scheduler.py:159` | Move `last_run_at` update into success path only; add `retry_count` field to `ReportSchedule` |
| 4 | MEDIUM | `shared/report_generator.py:297` | Re-raise exception from `html_to_pdf` instead of silently returning HTML bytes |

---

## Sprint Plan (37 items, ordered by value/effort)

### Sprint 1 — Bug Blitz (1–2 days)

Fix all bugs shipped in the latest commit plus open critical security issues.

- [ ] **#1** Fix `notify_email.py` MIME type — PDFs sent as `application/octet-stream`
- [ ] **#2** Fix `html_to_pdf()` blocking the event loop — wrap in `run_in_executor`
- [ ] **#3** Fix `last_run_at` updated on delivery failure (lost retries)
- [ ] **#4** Fix `report_generator.html_to_pdf` swallowing exceptions silently
- [ ] **#5** Remove hardcoded dashboard credentials (`admin@company.com` / `admin123`) — `services/dashboard/app/main.py`
- [ ] **#6** Enable Jinja2 autoescape — XSS on every dashboard template
- [ ] **#7** Admin guard on `POST /settings` — currently any authenticated user can overwrite all config
- [ ] **#8** Tenant filter on `/alerts/recent` and approval review (cross-tenant data leak)
- [ ] Add tests: email attachment MIME type test, report retry test

### Sprint 2 — Agents Come Alive (3–4 days)

The `OrchestrationEngine._registry` is empty. No agent handler is ever called. This is the #1 functional gap.

- [ ] **#9** Implement 8 agent handlers in `services/worker/app/agent_worker.py`:
  - `triage` — call LLM with alert context, store verdict in `AgentTask.output_data`
  - `ti_enrich` — query OTX/MISP for IOCs from task input, return enriched JSON
  - `ueba_check` — query UEBA anomaly score for user/host in alert
  - `case_create` — create Case record via internal API or direct DB insert
  - `soar_run` — execute playbook by name, return execution log
  - `notify` — send email/Slack/Teams notification with task output summary
  - `review` — peer-review previous task output; output `approved/rejected + reason`
  - `lead` — decompose task via LLM into sub-tasks, enqueue them, wait for results
- [ ] **#10** Output chaining in `shared/orchestrator/engine.py` — pass `prev_task.output_data` into each subsequent task's `input_data`
- [ ] **#11** `asyncio.gather` for independent parallel tasks in `execute_run()`
- [ ] **#12** Dynamic task decomposition via `lead` handler (LLM plans sub-tasks at runtime)
- [ ] **#13** Kanban HTMX view for agent runs in dashboard (live polling `/agents/runs`)
- [ ] **#14** Inject `user_feedback_negative_rate(rule_id)` into triage system prompt
- [ ] Add tests: handler unit tests, output chaining integration test

### Sprint 3 — Self-Learning Loop (3–4 days)

Wire existing feedback data back into agent behaviour so agents improve automatically.

- [ ] **#15** RAG skill memory — store each completed `AgentTask` (input/output/verdict) as a Qdrant chunk
- [ ] **#16** Retrieve top-K similar past tasks at inference time, inject as few-shot examples in prompt
- [ ] **#17** Prompt auto-refinement on analyst correction (SkillOpt pattern):
  - When analyst overrides triage verdict, record `(original_prompt, wrong_output, correct_output)`
  - Nightly job: generate improved prompt variant, A/B test for 24h, promote if better
- [ ] **#18** Nightly meta-agent: scan false negatives from feedback → add to RAG knowledge base
- [ ] **#19** Agent performance scoring — per-agent accuracy, latency, cost tracked in `AgentRun`
- [ ] **#20** Self-healing retry: on task failure, `lead` handler re-decomposes with failure context
- [ ] Add tests: feedback injection test, RAG retrieval accuracy benchmark

### Sprint 4 — Security Hardening (2–3 days)

Remaining critical/high findings from the 39-issue security audit.

- [ ] **#21** Signed session cookie via `itsdangerous.TimestampSigner` — replace plain JSON session
- [ ] **#22** CSRF middleware (`starlette-csrf` or manual double-submit) on all dashboard POST endpoints
- [ ] **#23** HashiCorp Vault for secrets — replace plaintext values in `settings.json` and `.env`
- [ ] **#24** Model swap: `phi4-mini` (fast tier) + `qwen2.5:7b` (full tier) + `deepseek-r1:8b` (reasoning tier)
- [ ] **#25** Force JSON schema output via Ollama `format` param — drop fragile bracket-depth parser
- [ ] **#26** LLM cross-provider failover in `TieredRouter` (Ollama → OpenAI → Gemini)
- [ ] **#27** Composite DB indexes on `(tenant_id, created_at)` for `alerts`, `cases`, `triage_results`, `agent_runs`, `audit_logs`
- [ ] Add tests: CSRF protection test, session forgery test, index query plan test

### Sprint 5 — New Capabilities (4–5 days)

Features the platform needs to become a one-stop cybersecurity solution.

- [ ] **#28** Prometheus `/metrics` endpoint — expose MTTR, MTTD, alert volume, LLM latency, agent queue depth
- [ ] **#29** MCP server layer — expose `list_alerts`, `get_triage`, `create_case`, `run_playbook` as MCP tools so Claude Desktop / Cursor can query the SOC natively
- [ ] **#30** Credential leak monitoring worker — HIBP API + paste site feed, alert on matches per tenant
- [ ] **#31** External attack surface scheduler — Shodan/Censys scan per tenant, store findings as `SurfaceAsset` records
- [ ] **#32** Sigma rule execution worker — compile Sigma rules to Wazuh Indexer DSL, run on schedule, generate alerts
- [ ] **#33** Evidence pack generation per case — signed PDF/ZIP with logs, triage, enrichment, timeline
- [ ] **#34** MITRE ATT&CK `tactic` and `technique_id` fields on `Alert` and `TriageResult` models
- [ ] Add tests: metrics endpoint test, MCP tool integration test

### Sprint 6 — Platform Maturity (4–5 days)

Advanced integrations and infrastructure for production-grade deployment.

- [ ] **#35** OpenCTI connector — replace manual IOC table with live threat intel feed
- [ ] **#36** CAPE sandbox connector — local malware analysis, replaces VirusTotal dependency
- [ ] **#37** Keycloak OIDC — replace hardcoded auth, add SSO + MFA for all tenants
- [ ] **#38** Honeytoken generation + monitoring — deploy decoy credentials, alert on use
- [ ] **#39** Security posture score (0–100 per tenant, real-time) — aggregate from open cases, patch lag, UEBA anomalies, credential leaks
- [ ] Full integration test suite refresh — target 85%+ coverage
- [ ] `docker-compose.local.yml` with Qdrant, OpenCTI, Keycloak, CAPE, Vault, Maigret

---

## Local AI Stack Recommendations

For fully local deployment (no external API calls):

| Role | Current | Recommended |
|------|---------|-------------|
| Fast triage | `qwen2.5-coder:3b` | `phi4-mini:3.8b` (better instruction following) |
| Full analysis | `qwen2.5-coder:7b` | `qwen2.5:7b` (broader knowledge) |
| Reasoning / lead | — | `deepseek-r1:8b` (chain-of-thought decomposition) |
| Embeddings | `nomic-embed-text` | `nomic-embed-text` (keep — best local option) |
| Vector store | in-memory | Qdrant (persistent, filterable, tenant-scoped) |

Add to `docker-compose.yml`:
```yaml
  qdrant:
    image: qdrant/qdrant:latest
    ports: ["6333:6333"]
    volumes: ["qdrant_data:/qdrant/storage"]

  keycloak:
    image: quay.io/keycloak/keycloak:24.0
    command: start-dev
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: "${KEYCLOAK_ADMIN_PASSWORD}"
    ports: ["8080:8080"]

  opencti:
    image: opencti/platform:6.x
    environment:
      APP__ADMIN__EMAIL: "${OPENCTI_ADMIN_EMAIL}"
      APP__ADMIN__PASSWORD: "${OPENCTI_ADMIN_PASSWORD}"
    ports: ["8083:8080"]

  vault:
    image: hashicorp/vault:latest
    cap_add: [IPC_LOCK]
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: "${VAULT_TOKEN}"
    ports: ["8200:8200"]
```

---

## Gaps vs. Market (One-Stop Platform)

Capabilities Wazuh lacks that this platform should cover:

| Domain | Gap | Implementation |
|--------|-----|----------------|
| Credential Leaks | No HIBP / paste monitoring | Sprint 5 #30 |
| Attack Surface | No external exposure mapping | Sprint 5 #31 |
| Threat Intel | Manual IOC only | Sprint 6 #35 (OpenCTI) |
| Malware Analysis | VT-dependent | Sprint 6 #36 (CAPE local) |
| Compliance | No automated evidence collection | Sprint 5 #33 (evidence packs) |
| Identity | Hardcoded auth | Sprint 6 #37 (Keycloak) |
| Deception | No honeytokens | Sprint 6 #38 |
| Posture | No risk score | Sprint 6 #39 |
| Detection Engineering | No Sigma runner | Sprint 5 #32 |
| AI Integration | No MCP / tool interface | Sprint 5 #29 |
| Observability | No metrics endpoint | Sprint 5 #28 |
| Secrets Management | Plaintext .env | Sprint 4 #23 (Vault) |

---

## Files to Touch Per Sprint

### Sprint 1
- `shared/connectors/notify_email.py` — MIME fix
- `services/worker/app/report_scheduler.py` — async fix + retry logic
- `shared/report_generator.py` — exception propagation
- `services/dashboard/app/main.py` — remove hardcoded creds, autoescape
- `services/api/app/routers/settings.py` — admin guard
- `services/api/app/routers/alerts.py` — tenant filter
- `services/api/app/routers/approvals.py` — tenant filter

### Sprint 2
- `services/worker/app/agent_worker.py` — 8 handler implementations
- `shared/orchestrator/engine.py` — output chaining, parallel execution
- `services/dashboard/app/templates/agents.html` — kanban view
- `services/worker/app/triage_worker.py` — inject feedback rate

### Sprint 3
- `shared/rag/skill_memory.py` (new) — task chunk storage
- `shared/orchestrator/engine.py` — few-shot retrieval at inference
- `services/worker/app/prompt_refiner.py` (new) — SkillOpt loop
- `services/worker/app/meta_agent.py` (new) — nightly false-negative scan

### Sprint 4
- `services/dashboard/app/middleware/session.py` — signed cookies
- `services/dashboard/app/middleware/csrf.py` — CSRF tokens
- `shared/secrets.py` (new) — Vault client wrapper
- `shared/config.py` — pull secrets from Vault at startup
- `shared/models/*.py` — add composite index definitions

### Sprint 5
- `services/api/app/routers/metrics.py` (new) — Prometheus endpoint
- `services/mcp/server.py` (new) — MCP tool definitions
- `services/worker/app/credential_leak_worker.py` (new)
- `services/worker/app/attack_surface_worker.py` (new)
- `services/worker/app/sigma_worker.py` (new)
- `shared/models/alert.py` — add `technique_id`, `tactic` fields

### Sprint 6
- `shared/connectors/opencti.py` (new)
- `shared/connectors/cape_sandbox.py` (new)
- `services/api/app/routers/auth.py` — OIDC flow via Keycloak
- `services/worker/app/honeytoken_worker.py` (new)
- `services/api/app/routers/posture.py` (new)
- `docker-compose.local.yml` (new)
