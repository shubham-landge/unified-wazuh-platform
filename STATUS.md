# Unified Wazuh SOC Platform — Build Status

> **Project Board**: https://github.com/users/shubham-landge/projects/1
> **Repository**: https://github.com/shubham-landge/unified-wazuh-platform
> **Updated**: 2026-06-11

---

## Claude — Architecture Review + Connectors + Workers

| Field | Value |
|---|---|
| **Branch** | `tool/claude` |
| **PR** | — |
| **Status** | ✅ Complete |
| **Task** | Security/architecture review (P0-P2 fixes), 4 notification connectors, notification worker, SOAR engine, 3 TI connectors, TI worker, UEBA engine, health registry |
| **Files created** | `shared/connectors/notify_{email,slack,teams,pagerduty}.py`, `shared/connectors/ti_{alienvault,misp,virustotal}.py`, `shared/soar/engine.py`, `shared/soar/actions.py`, `shared/ueba/baseline.py`, `shared/ueba/detector.py`, `shared/health_registry.py`, `services/worker/app/{notification_worker,threat_intel_worker}.py`, `shared/models/{threat_intel,ueba,playbook}.py`, `tests/test_{notification_connectors,threat_intel,soar_engine,ueba}.py` |
| **Files modified** | `shared/config.py`, `shared/connectors/llm_provider.py`, `services/api/app/main.py`, `services/api/app/middleware/{auth,audit,dashboard_access}.py`, `services/api/app/routers/{triage,health}.py`, `services/worker/app/{triage_worker,poller}.py`, `database/schema.sql`, `.env.example` |
| **Blockers** | None |

## Codex — Backend Builder

| Field | Value |
|---|---|
| **Branch** | `tool/codex` |
| **PR** | — |
| **Status** | 📝 Not Started |
| **Task** | Cloud LLM providers (OpenAI, Gemini, Claude), EPSS/KEV enrichment engine, report generator module |
| **Files to create** | `shared/connectors/llm_openai.py`, `llm_gemini.py`, `llm_claude.py`, `services/worker/app/vulnerability_worker.py`, `shared/report_generator.py` |
| **Blockers** | None |

## Antigravity — Dashboard & Docs

| Field | Value |
|---|---|
| **Branch** | `tool/antigravity` |
| **PR** | #1 |
| **Status** | ✅ Complete | PR: #1 |
| **Task** | Dashboard enhancements (charts, settings page), deployment documentation |
| **Files to create/modify** | Dashboard templates, `docs/DASHBOARD-GUIDE.md`, `docs/DEPLOYMENT-GUIDE.md` |
| **Blockers** | None |

## OpenCode — Integration & Deploy

| Field | Value |
|---|---|
| **Branch** | `tool/opencode` |
| **PR** | — |
| **Status** | 🔄 Ready |
| **Task** | End-to-end testing, Docker build verification, EC2 deployment scripts |
| **Blockers** | Waiting for other tools to complete first |

---

## Merge Order

```
1. tool/claude  ──> dev   (review + approve by Shubham)
2. tool/codex   ──> dev   (after Claude approval)
3. tool/antigravity ──> dev (after Codex merges)
4. tool/opencode ──> dev   (final integration)
5. dev ──> main           (after all tests pass)
```

## Status Legend

| Icon | Meaning |
|---|---|
| 📝 | Not Started |
| 🔄 | In Progress |
| ✅ | Complete |
| ⏸ | Blocked / On Hold |
