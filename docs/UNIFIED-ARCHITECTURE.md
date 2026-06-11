# Unified Architecture

## System Overview

The Unified Wazuh Security Operations Platform is a read-only AI-powered SOC triage and vulnerability management layer that sits on top of an existing Wazuh 4.14.4 deployment. It enhances Wazuh with commercial-grade case management, AI analysis, vulnerability prioritization, compliance dashboards, and executive reporting — without modifying Wazuh itself.

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      AWS EC2 m7i.2xlarge                            │
│                     (8 vCPU, 32 GB RAM, no GPU)                     │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Docker Compose Stack                       │   │
│  │                                                               │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │   │
│  │  │  FastAPI  │  │  Worker  │  │ Ollama   │  │  Dashboard   │ │   │
│  │  │  (Port    │  │  (Alert  │  │ (Local   │  │  (Port 80)   │ │   │
│  │  │   8000)   │  │  Poller) │  │  LLM)    │  │  Jinja+HTMX  │ │   │
│  │  └─────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘ │   │
│  │        │              │             │               │          │   │
│  │  ┌─────┴──────────────┴─────────────┴───────────────┴──────┐  │   │
│  │  │                    PostgreSQL + Redis                     │  │   │
│  │  └──────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │           │                              │
└──────────────────────────────┼───────────┼──────────────────────────────┘
                               │           │
                    ┌──────────┘           └──────────┐
                    ▼                                  ▼
        ┌──────────────────────┐         ┌──────────────────────┐
        │  Wazuh Manager-1     │         │  Wazuh Indexer-1     │
        │  172.16.2.130:55000  │         │  172.16.6.179:9200   │
        │                      │         │                      │
        │  Wazuh Manager-2     │         │  Wazuh Indexer-2     │
        │  172.16.2.192:55000  │         │  172.16.6.126:9200   │
        └──────────────────────┘         │                      │
                                          │  Wazuh Indexer-3     │
                                          │  172.16.2.87:9200    │
                                          └──────────────────────┘
```

## Component Descriptions

### FastAPI Backend (`services/api/`)
- **Framework**: FastAPI (Python 3.12)
- **ORM**: SQLAlchemy 2.0 async + asyncpg
- **Auth**: API key-based (X-API-Key header)
- **Rate Limiting**: 100 req/min per key
- **Serves**: REST API + dashboard static files + API routes

### Background Worker (`services/worker/`)
- **Alert Poller**: Polls Wazuh Indexer every 60s for new alerts
- **Triage Worker**: Processes alerts through LLM (local Ollama or cloud)
- **Vulnerability Worker**: Syncs CVE data from Wazuh VM module
- **Technology**: Python async workers consuming Redis queue

### Ollama (`ollama/`)
- **Models**: qwen2.5-coder:3b (fast triage), qwen2.5-coder:7b (deep analysis)
- **Embedding**: nomic-embed-text for future RAG
- **API**: Standard Ollama HTTP API on port 11434
- **Access**: Private network only (not exposed to internet)

### Database
- **PostgreSQL 16**: Primary data store (cases, alerts, assets, vulnerabilities, audit)
- **Redis 7**: Queue, cache, rate limiting

### Dashboard (`services/dashboard/`)
- **Rendering**: Jinja2 templates (server-side rendered)
- **Interactivity**: HTMX + Alpine.js (no build step)
- **CSS**: Tailwind CSS via CDN
- **Theme**: Dark mode SOC theme

## Data Flow

### Alert → Triage → Case

```
1. Wazuh Indexer receives alert from Manager
2. Alert Poller queries Indexer every 60s (read-only, last N alerts)
3. Poller normalizes alert into standardized format
4. Poller extracts entities (IPs, users, hosts, processes, file hashes)
5. Poller stores normalized alert in PostgreSQL `alerts` table
6. Poller publishes alert ID to Redis triage queue
7. Triage Worker consumes queue item
8. Worker applies sensitive data masking (IPs, usernames, etc.)
9. Worker sends masked alert to LLM with triage prompt
10. LLM returns JSON: {summary, category, severity, MITRE, FP, steps, escalation}
11. Worker validates JSON structure and required fields
12. Worker stores result in `ai_triage_results` table
13. Worker creates case in `cases` table if escalation needed
14. Worker logs audit entry in `audit_log` table
15. Dashboard displays case for SOC analyst
16. Analyst reviews, adds notes, closes or escalates
```

### Vulnerability Management Flow

```
1. Vulnerability Worker queries Wazuh Indexer for CVE data
2. Worker normalizes vulnerability records
3. Worker enriches with EPSS score (if API available) and CISA KEV
4. Worker calculates risk score: CVSS * asset_criticality * exploitability
5. Worker stores in `vulnerabilities` table
6. Dashboard shows prioritized vulnerability list
7. Analyst assigns patch SLA and owner
8. Patch completion verified on next scan cycle
```

## Multi-Tenancy Design

All database tables include `tenant_id` (UUID) as the first column:
- Every query filters by `tenant_id` from the API key
- Each API key is bound to a single tenant
- Dashboard shows only the tenant's data
- Future: separate DB schemas per tenant if needed

## Security Principles

1. **Read-only Wazuh connection** — no active response, agent delete, or Wazuh config changes
2. **No secrets in code** — all credentials in `.env` file (never committed)
3. **Sensitive data masking** — IPs, usernames, file paths masked before LLM calls
4. **Full audit trail** — every AI decision stored with prompt, response, model, timestamp
5. **No autonomous destructive actions** — Phase 1 is read-only analysis only
6. **API key authentication** — all endpoints require valid API key
7. **Rate limiting** — prevents abuse
8. **Dashboard access restricted** — CIDR-based access control

## LLM Provider Abstraction

```
┌──────────────┐
│  LLMProvider  │  (Abstract Base Class)
├──────────────┤
│  + analyze() │
│  + health()  │
└──────┬───────┘
       │
       ├─── OllamaProvider
       │     ├── qwen2.5-coder:7b (primary)
       │     └── qwen2.5-coder:3b (fast fallback)
       │
       ├─── OpenAIProvider
       │     └── gpt-4o (optional cloud fallback)
       │
       ├─── GeminiProvider
       │     └── gemini-2.5-flash (optional)
       │
       └─── ClaudeProvider
             └── claude-3-5-sonnet (optional)
```

## Future Phases

| Phase | Components | When |
|---|---|---|
| Phase 2 | RAG (turbovec + Cybersecurity Skills), Compliance Dashboard | After MVP validated |
| Phase 3 | OSINT (maigret in CubeSandbox), Multi-agent orchestration | After RAG stable |
| Phase 4 | Human-approved response actions, Ticketing integrations | After all validation |
| Phase 5 | Multi-tenant MSP mode, White-label, Commercial licensing | After production stability |
