# Unified Wazuh SOC Platform — Build Status

> **Project Board**: https://github.com/users/shubham-landge/projects/1
> **Repository**: https://github.com/shubham-landge/unified-wazuh-platform
> **Updated**: 2026-06-11

---

## Claude — Architecture Review

| Field | Value |
|---|---|
| **Branch** | `tool/claude` |
| **PR** | — |
| **Status** | 📝 Not Started |
| **Task** | Review architecture, security hardening, prompt templates, database schema |
| **Files to review** | `shared/`, `database/schema.sql`, `services/api/app/routers/*`, `services/api/app/middleware/*`, `docker-compose.yml` |
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
