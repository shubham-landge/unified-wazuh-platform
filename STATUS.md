# Unified Wazuh SOC Platform — Build Status

> **Project Board**: https://github.com/users/shubham-landge/projects/1
> **Repository**: https://github.com/shubham-landge/unified-wazuh-platform
> **Updated**: 2026-06-13

---

## Claude — Architecture Review

| Field | Value |
|---|---|
| **Branch** | `tool/claude` |
| **PR** | Merged to `dev` |
| **Status** | ✅ Complete |
| **Fixes applied** | P0: triage worker crash, dead-letter queue, prompt file loading, real LLM wiring, 202 response, GET endpoint, removed hardcoded API key, updated claude_model. P1: CORS fix, SHA-256 hash auth, key prefix audit logging, CIDR whitelist-only dashboard. P2: SSL verify default True, bracket-depth JSON parser, base64 regex removed, dateutil timestamp parse, offset pagination. |
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
| **Blockers** | None — can proceed in parallel with Codex |

---

## Merge Order

```
1. ✅ tool/antigravity ──> dev  (PR #1 — merged)
2. ✅ tool/claude      ──> dev  (merged)
3. 🔄 tool/codex       ──> dev  (in progress — cloud LLM, EPSS/KEV, reports)
4. 🔄 tool/opencode    ──> dev  (in progress — tests, Docker build, deploy prep)
5. ⏳ dev ──> main              (after Codex + OpenCode complete, all tests pass)
```

## Status Legend

| Icon | Meaning |
|---|---|
| 📝 | Not Started |
| 🔄 | In Progress |
| ✅ | Complete |
| ⏸ | Blocked / On Hold |
