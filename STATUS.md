# Unified Wazuh SOC Platform — Build Status

> **Project Board**: https://github.com/users/shubham-landge/projects/1
> **Repository**: https://github.com/shubham-landge/unified-wazuh-platform
> **Updated**: 2026-06-17

---

## Phase 1 — Core Infrastructure

| Tool | What was built | Status |
|---|---|---|
| Claude | Architecture review, P0-P2 fixes: triage worker crash, dead-letter queue, prompt loading, real LLM wiring, SHA-256 auth, CIDR whitelist, bracket-depth JSON parser | ✅ main |
| Antigravity | 5 architecture diagrams, SOC playbook guide, deployment guide, report/email templates, settings/landing pages | ✅ main |
| OpenCode | All-mocked tests, /health no-auth, unified worker entrypoint, EC2 scripts with validation, healthcheck, rollback | ✅ main |
| Codex | OpenAI/Gemini/Claude connectors, EPSS/KEV enrichment, report generator, notification/SOAR/TI/UEBA models+routers, schema | ✅ main |

## Phase 2 — Dashboard UI v2 + Workers v2

| Tool | What was built | Status |
|---|---|---|
| Antigravity | 7 dashboard screens (compliance, notifications, playbooks, threat intel, health), chart visualizations, dashboard store | ✅ main |
| Claude | 4 notification connectors, notification worker, SOAR engine + actions, 3 TI connectors, TI worker, UEBA baseline + anomaly detector, health registry | ✅ main |

## Phase 3A — Authentication & RBAC

| Tool | What was built | Status |
|---|---|---|
| Claude | RBAC, User model, JWT auth, OIDC support, tenant enforcement, alert dedup, report scheduler | ✅ main |
| Antigravity | Login, profile, user management, report scheduler dashboard UI | ✅ main |

## Phase 3B — Feedback Loop & Tiered Routing

| Tool | What was built | Status |
|---|---|---|
| Claude | UserFeedback model, feedback worker, auto-calibration, tiered LLM router (fast/full), burst detection | ✅ main |
| Antigravity | Dashboard feedback UI — thumbs up/down, correction form, admin feedback analytics page | ✅ main |

## Phase 4A — Case Timeline & Investigation

| Tool | What was built | Status |
|---|---|---|
| Claude | CaseEvent, CaseInvestigationStep models, timeline/steps endpoints, risk scoring in triage worker | ✅ main |
| Antigravity | Timeline UI, investigation checklist with HTMX, bulk status fix | ✅ main |
| Codex | Model tests, timeline endpoint tests, risk score tests, dashboard rendering tests | ✅ main |

## Phase 4B — MTTR Dashboard & ATT&CK Heatmap

| Tool | What was built | Status |
|---|---|---|
| Antigravity | MTTR Analytics Dashboard, MITRE ATT&CK Heatmap matrix, case status breakdown charts | ✅ main |

## Phase 5A — RAG & Compliance Dashboard

| Tool | What was built | Status |
|---|---|---|
| OpenCode | KnowledgeChunk model, embedding/cosine-similarity, vector store (search/ingest/chunk), RAG API (query/list/ingest/delete), RAG worker (Redis queue, KB seed), Compliance framework/control/mapping/exception models, compliance checker, compliance API, compliance dashboard UI | ✅ main |

## Phase 6 — Remaining Features (Parallel Tracks)

| Track | Tool | What was built | Status |
|---|---|---|---|
| OSINT Integration | Codex | Maigret connector, OSINT lookup API, OSINT worker, OSINT dashboard page | ✅ main |
| MCP / Wazuh Direct Tools | Codex | Direct Wazuh API and Indexer MCP tools with circuit breaker and dispatcher | ✅ main |
| Multi-Agent Orchestration | Claude | Agent definition/run/task models, orchestration engine, agent worker, agents dashboard | ✅ main |
| Human-Approved Actions | Antigravity | ApprovalRequest model, approvals API, approval worker with expiry, approvals dashboard UI | ✅ main |
| Ticketing Integrations | OpenCode | ServiceNow + Jira connectors, ticketing config/model API, ticketing sync worker, ticketing settings dashboard | ✅ main |
| RAG Fixes & Dashboard | OpenCode | Model/schema consistency fixes, Knowledge Base dashboard UI, integration tests | ✅ main |
| Tenant API + Super Admin (Track A) | OpenCode | Tenant CRUD API, role-based super admin check, cross-tenant admin views, real stats | ✅ main |
| White-Label Branding (Track D) | OpenCode | Branding API (colors/logo/css per tenant), dashboard theming via CSS vars, branding settings tab | ✅ main |
| Usage Metering (Track E) | OpenCode | Per-tenant usage limits via config, metering middleware, super admin multi-tenant usage endpoint | ✅ main |
| Schema + Model Consistency (Track F) | OpenCode | All 47 models use TenantMixin or NullableTenantMixin — track complete | ✅ main |

---

## Test Suite: 223 passing, 0 failing

All tests run fully mocked — no Docker, no DB, no Redis required.

## Status Legend

| Icon | Meaning |
|---|---|
| ✅ | Complete (merged to main) |
| 🔄 | In Progress |
| 📝 | Not Started |
| ⏸ | Blocked / On Hold |
