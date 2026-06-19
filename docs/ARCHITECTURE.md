# Architecture — Wazuh-Overlay AI SOC

> **One line:** This platform sits *on top of* a Wazuh deployment. It does the
> things Wazuh can't (autonomous AI SOC) **and** watches the Wazuh environment's
> own health — without replacing or forking Wazuh.

It is **not** a Wazuh replacement. Wazuh remains the source of truth for
detection, agents, and log storage. This platform reads from Wazuh, reasons over
it, and acts — and tells you when Wazuh itself is unwell.

---

## The two halves

```
                         ┌───────────────────────────────────────────────┐
                         │         UNIFIED WAZUH-OVERLAY AI SOC           │
                         │        (one EC2 box, Docker Compose)           │
                         │                                               │
   ┌──────────┐  read    │   ┌─────────────────────┐  ┌────────────────┐ │
   │  Wazuh   │ ───────► │   │  AI SOC             │  │ Wazuh          │ │
   │ Manager  │  API     │   │  (what Wazuh can't) │  │ Observability  │ │
   │  :55000  │          │   │                     │  │ (watch Wazuh)  │ │
   └──────────┘          │   │ • tiered triage     │  │ • agent        │ │
   ┌──────────┐  read    │   │   qwen→notmythos→   │  │   connectivity │ │
   │  Wazuh   │ ───────► │   │   Gemini(cloud)     │  │ • manager /    │ │
   │ Indexer  │  _search │   │ • cross-domain      │  │   cluster /EPS │ │
   │  :9200   │          │   │   stitching         │  │ • indexer /    │ │
   └──────────┘          │   │ • identity / ITDR   │  │   ingestion lag│ │
                         │   │ • autonomous agents │  │ • pipeline SLAs│ │
   ┌──────────┐  act     │   │ • RAG + few-shot    │  │                │ │
   │ Identity/│ ───────► │   │ • SOAR (gated)      │  │ → alerts when  │ │
   │ Cloud    │  ingest  │   └─────────────────────┘  │   Wazuh sick   │ │
   │ (Entra,  │          │            │                └────────────────┘ │
   │ O365,    │          │            ▼                                   │
   │ Graph,   │          │   Postgres · Redis · Ollama (CPU) · MCP        │
   │ CloudTrl)│          │                                               │
   └──────────┘          └───────────────────────────────────────────────┘
```

### Half 1 — AI SOC (what Wazuh can't do)

| Capability | Where |
|---|---|
| **Tiered LLM triage**, CPU-first | `shared/connectors/llm_router.py` — qwen (fast/noise-gate) → notmythos (full) → **Gemini cloud escalation** for cross-domain/hardest cases |
| **Noise-reduction pre-gate** (keep/drop/downgrade) | `shared/noise_reduction.py` — protects the CPU triage budget |
| **Cross-domain entity stitching** + kill-chain stage | `shared/correlation/` |
| **Parallel enrichment** → evidence pack before the LLM | `shared/orchestrator/enrichment.py` |
| **Identity / ITDR** (7 detections) | `services/worker/app/identity_worker.py`, `shared/connectors/{entra,o365,msgraph,cloudtrail}.py` |
| **Autonomous agents** (orchestration, autonomy levels, policy guard) | `shared/orchestrator/`, `services/worker/app/agent_worker.py` |
| **RAG + few-shot** (ATT&CK skills) | `shared/rag/`, `scripts/seed_attack_skills.py` |
| **SOAR / containment** — always gated by policy_guard + approvals | `shared/soar/`, `shared/orchestrator/handlers.py` |
| **Self-learning** (SkillOpt prompt refinement, feedback-aware triage) | `services/worker/app/prompt_refiner.py`, triage handler |

### Half 2 — Wazuh Observability (watch Wazuh itself)

The capability Wazuh's own UI surfaces poorly. `wazuh_health_worker` polls every
120s and writes a `WazuhHealthSnapshot`, raising internal alerts when Wazuh
degrades.

| Signal group | What we track | Source |
|---|---|---|
| **Agent connectivity** | active / disconnected / never-connected / pending | `WazuhAPIConnector.get_agents_summary` |
| **Manager & cluster** | daemon run-state, cluster health, analysisd EPS / queue / dropped events | `get_manager_status`, `get_cluster_health`, `get_manager_stats` |
| **Indexer & ingestion** | cluster status (green/yellow/red), unassigned shards, ingestion lag | `WazuhIndexerConnector.cluster_health`, `ingestion_lag_seconds` |
| **Pipeline SLAs** (self) | poller heartbeat lag, triage queue depth | Redis (`poller:last_run`, `triage_queue`) |

Surfaced at: API `GET /wazuh/environment` (+ `/history`), dashboard
`/wazuh-environment`, and Prometheus gauges (`soc_wazuh_*`, `soc_poller_lag_seconds`).

---

## Runtime (one EC2 box, CPU-only + cloud escalation)

`docker-compose.yml` on an m6i.2xlarge-class instance (8 vCPU / 32 GB):

| Container | Role |
|---|---|
| `postgres` | platform state |
| `redis` | queues, cache, gauge hand-off, sessions |
| `ollama` | local LLMs (qwen fast, notmythos full, nomic embeddings) — the always-on CPU tiers |
| `api` | FastAPI REST (`:8000`) |
| `worker` | poller, triage, identity, **wazuh_health**, UEBA, RAG, SOAR, ticketing, … |
| `dashboard` | HTMX SOC UI (`:80`) |
| `mcp` | MCP server (`:9000`) — 14 tools for LLM agents |
| `maigret` | OSINT username lookups |

**LLM tiering & cost control.** Local qwen → notmythos handle the vast majority
on CPU. Only **cross-domain/advancing incidents** or very high routing scores
escalate to **Gemini** (`LLM_TIER_ESCALATION_ENABLED`, default off). This keeps
the CPU-only baseline intact and cloud spend bounded. Set `GEMINI_API_KEY` +
`LLM_TIER_ESCALATION_ENABLED=true` to turn it on. Forced JSON output (Ollama
`format:json`, Gemini `responseMimeType`) keeps triage parsing reliable.

**Multi-tenancy.** Every read is tenant-scoped via `require_tenant_uuid`; missing
tenant context is rejected (400), never silently widened.

---

## End-to-end smoke test

```bash
# 1. Wazuh environment snapshot is being collected
curl -H "X-API-Key: $KEY" http://<EC2>:8000/wazuh/environment | jq .snapshot.overall_status

# 2. Dashboard renders the environment view
open http://<EC2>/wazuh-environment           # agents / manager / indexer / SLA panels

# 3. Prometheus exposes Wazuh-health gauges
curl -H "X-API-Key: $KEY" http://<EC2>:8000/metrics | grep soc_wazuh_

# 4. Escalation routes to cloud only when enabled (else stays local)
#    set LLM_TIER_ESCALATION_ENABLED=true + GEMINI_API_KEY, feed a cross-domain incident

# 5. Tenant isolation holds
curl -H "X-API-Key: $KEY" http://<EC2>:8000/alerts/<other-tenant-alert-id>   # → 404

# 6. Full suite
python -m pytest -q                            # 343 passing
```

---

## Related

[VISION-AUTONOMOUS-SOC.md](VISION-AUTONOMOUS-SOC.md) ·
[PHASE-9-DETECTION-BEYOND-ENDPOINT.md](PHASE-9-DETECTION-BEYOND-ENDPOINT.md) ·
[MULTI-TOOL-PLAN.md](MULTI-TOOL-PLAN.md) ·
[operations/DEPLOYMENT-PLAN.md](operations/DEPLOYMENT-PLAN.md)
