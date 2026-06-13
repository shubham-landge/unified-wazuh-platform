# Unified Wazuh SOC Platform — Build Status

> **Project Board**: https://github.com/users/shubham-landge/projects/1
> **Repository**: https://github.com/shubham-landge/unified-wazuh-platform
> **Updated**: 2026-06-13

---

## Phase 1 — Complete (merged to main)

| Phase | Tool | What was built | Status |
|---|---|---|---|
| Architecture Review | Claude | P0-P2 fixes: triage worker crash, dead-letter queue, prompt loading, real LLM wiring, 202 response, SHA-256 auth, CIDR whitelist, bracket-depth JSON parser, dateutil timestamps, offset pagination | ✅ main |
| Dashboard & Docs | Antigravity | 5 architecture diagrams, SOC playbook guide, deployment guide, report/email templates, settings/landing pages | ✅ main |
| Integration & Tests | OpenCode | 56 tests passing (all mocked, no Docker/DB), /health no-auth, unified worker entrypoint, EC2 scripts with validation, healthcheck, port checks, rollback | ✅ main |
| Cloud LLM + EPSS/KEV + Reports + Models/Routers | Codex | OpenAI/Gemini/Claude connectors with cost tracking, EPSS/KEV enrichment worker, report generator (Jinja2→PDF) with CRUD API, notification/SOAR/threat-intel/UEBA models+routers, database schema | ✅ main |

## Remaining — to build (parallel)

### Claude — Workers & Connectors (~20 files)

| Deliverable | Files | Details |
|---|---|---|
| Notification Connectors | `shared/connectors/email.py`, `slack.py`, `teams.py`, `pagerduty.py` | Email (SMTP/aiosmtplib), Slack, Teams (adaptive cards), PagerDuty (Events API v2) |
| Notification Worker | `services/worker/app/notification_worker.py` | Reads Redis `notifications_queue`, dispatches via correct connector, DLQ |
| SOAR Playbook Engine | `shared/playbook_engine.py` | Trigger matching, ordered task execution (create_case, send_notification, webhook, wait, run_script) |
| Playbook Worker | `services/worker/app/playbook_worker.py` | Reads Redis `playbook_queue`, executes playbooks with timeout handling |
| Threat Intel Connectors | `shared/connectors/alienvault_otx.py`, `misp.py`, `virustotal.py` | OTX lookup, MISP search, VirusTotal IP/hash lookup |
| Threat Intel Worker | `services/worker/app/threat_intel_worker.py` | Feed polling (6h), alert IoC enrichment, rate-limit handling |
| UEBA Engine | `shared/ueba/baseline.py` | z-score baseline computation, anomaly detection |
| UEBA Worker | `services/worker/app/ueba_worker.py` | Daily baseline computation, anomaly creation, notification triggers |
| Health Monitoring | `shared/health_registry.py`, `shared/connectors/redis_health.py` | Cached parallel health checks, health() methods on wazuh_api/indexer connectors |
| Notification Templates | `services/api/app/prompts/templates/notifications/` | Email HTML, Slack text, Teams card, PagerDuty incident templates |
| Tests | 6 new test files | notification connectors + worker, playbook engine, TI connectors, UEBA engine, health registry |
| Doc | `docs/ARCHITECTURE-REVIEW-CODEX.md` | Security, performance, reliability, consistency review |

### Antigravity — Dashboard UI (~16 files)

| Deliverable | Files | Details |
|---|---|---|
| Notifications UI | `templates/notifications.html` | Channels/rules/events tabs, CRUD modals, enable/disable toggles |
| Compliance Dashboard | `templates/compliance.html`, `compliance_detail.html` | SOC2/PCI-DSS/HIPAA/NIST framework viewer, control→alert/vuln mapping, evidence upload |
| Playbook Builder | `templates/playbooks.html`, `playbook_detail.html`, `playbook_execution_detail.html` | Alpine.js drag-and-drop builder, trigger config, execution timeline |
| Threat Intel Pages | `templates/threat_intel.html`, `threat_intel_ioc_detail.html`, `threat_intel_feeds.html` | IoC search, feed management, indicator detail |
| Health Page | `templates/health.html` | Integration status grid with 30s auto-refresh |
| Charts | `static/charts.js` | Alert severity, vulnerability trend, case resolution, MITRE techniques |
| Integration | `dashboard/main.py` updates | Wire new routes, nav items in base.html, update reports.html to use live API |
| Tests | 1 new test file | Dashboard route rendering |

---

## Merge Order

```
Status: main at 301eb44 — Phase 1 fully merged
─────────────────────────────────────────────────
Next: Clone tool/claude branch from main (workers + connectors + review)
      Clone tool/antigravity branch from main (dashboard UI + templates)
      Run both in parallel — no file conflicts between them
      Each PRs into main independently
```

## What already works (56 tests passing)

- `/health` — no auth required (Docker HEALTHCHECK)
- `/vulnerabilities` — list/filter by status/severity/CVE/asset
- `/reports` — generate, list, download (HTML/PDF with WeasyPrint)
- `/notifications/channels`, `/notifications/rules` — CRUD
- `/playbooks` — CRUD with tasks
- `/threat-intel/indicators`, `/threat-intel/feeds` — CRUD + lookup
- `/ueba/baselines`, `/ueba/anomalies` — list + status update
- `/wazuh/health`, `/model/status` — enhanced health endpoints
- AI triage via OpenAI/Gemini/Claude/Ollama with cost tracking
- EPSS (FIRST.org) + CISA KEV daily enrichment with risk scoring
- Alert polling from Wazuh Indexer → Redis → triage worker
- All mocked tests — no Docker/DB/Redis required for test suite

## Status Legend

| Icon | Meaning |
|---|---|
| ✅ | Complete (merged to main) |
| 🔄 | In Progress |
| 📝 | Not Started |
| ⏸ | Blocked / On Hold |
