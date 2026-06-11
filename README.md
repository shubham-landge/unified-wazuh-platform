# Unified Wazuh Security Operations & Vulnerability Management Platform

An AI-powered SOC operations and vulnerability management layer for Wazuh. Turns Wazuh into an enterprise-grade security operations platform with AI triage, vulnerability management, case management, compliance dashboards, and human-approved automation.

## Architecture

```
                     ┌─────────────────────────────────┐
                     │     m7i.2xlarge (8 vCPU, 32GB)   │
                     │                                  │
┌──────────┐         │  ┌────────┐  ┌───────────────┐  │
│  Wazuh   │◄────────┼──┤ Wazuh  │  │  Dashboard    │  │
│ Manager  │ 55000   │  │ MCP    │  │  (Jinja+HTMX) │  │
│ 4.14.4   │         │  │ Wrapper│  └───────┬───────┘  │
├──────────┤         │  └───┬────┘          │          │
│  Wazuh   │◄────────┼──┐   │               │          │
│ Indexer  │ 9200    │  │   ▼               │          │
│ 4.14.4   │         │  │  ┌────────────────┴────┐     │
└──────────┘         │  │  │   FastAPI Backend    │     │
┌──────────┐         │  │  │   + Workers          │     │
│ Wazuh    │         │  │  └────────┬─────────────┘     │
│ Agents   │         │  │           │                   │
└──────────┘         │  │  ┌────────┴─────────────┐     │
                     │  │  │   PostgreSQL + Redis  │     │
                     │  │  └──────────────────────┘     │
                     │  │                               │
                     │  │  ┌──────────────────────┐     │
                     │  └──┤   Ollama (Local LLM)  │     │
                     │     │ qwen2.5-coder:3b/7b   │     │
                     │     └──────────────────────┘     │
                     └──────────────────────────────────┘
```

## Features

- **AI SOC Triag** — Automatic Wazuh alert summarization, classification, MITRE mapping
- **Vulnerability Management** — CVE inventory, CVSS/EPSS/KEV enrichment, risk scoring
- **Case Management** — Incident tracking, analyst notes, status workflow
- **Asset Inventory** — Agent status, OS, groups, vulnerability count
- **Compliance Dashboard** — SCA findings, CIS/NIST mapping
- **Audit Logging** — Full traceability of all platform actions
- **Executive Reporting** — PDF/Excel report generation
- **Human-in-the-Loop** — Read-only Phase 1, no autonomous destructive actions
- **Multi-Tenant Ready** — Tenant isolation built into schema from day one

## Quick Start

```bash
# 1. Clone
git clone https://github.com/shubham-landge/unified-wazuh-platform.git
cd unified-wazuh-platform

# 2. Configure
cp .env.example .env
# Edit .env with your Wazuh read-only credentials

# 3. Start
docker compose up -d

# 4. Verify
curl http://localhost:8000/health

# 5. Pull Ollama models (first time only)
docker compose exec ollama ollama pull qwen2.5-coder:3b
docker compose exec ollama ollama pull qwen2.5-coder:7b
```

## Documentation

| Document | Purpose |
|---|---|
| [Architecture](docs/UNIFIED-ARCHITECTURE.md) | Full system architecture and data flow |
| [Vulnerability Management](docs/VULNERABILITY-MANAGEMENT-MODULE.md) | CVE enrichment, risk scoring, patch SLA |
| [Security Hardening](docs/SECURITY-HARDENING.md) | Security rules and implementation guide |
| [Repo Audit](docs/REPO-AUDIT-MATRIX.md) | Audit of all integrated repositories |

## API Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | System health |
| GET | `/wazuh/health` | Wazuh connection status |
| GET | `/alerts/recent` | Recent alerts with AI triage |
| GET | `/alerts/{id}` | Alert detail |
| POST | `/triage/run` | Run AI triage on alert |
| GET | `/cases` | Case list |
| GET | `/cases/{id}` | Case detail |
| POST | `/cases/{id}/notes` | Add analyst note |
| GET | `/assets` | Asset inventory |
| GET | `/vulnerabilities` | Vulnerability list |
| GET | `/audit` | Audit log |

## License

MIT
