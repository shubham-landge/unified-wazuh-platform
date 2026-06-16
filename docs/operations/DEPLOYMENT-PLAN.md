# Production Deployment & Capacity Plan — Payless SOC

Scale-out plan for the autonomous SOC platform layered on the existing Wazuh
cluster. Reconciled against the official architecture briefing
*"Wazuh SIEM Platform — Architecture & Roadmap"* (real environment data:
Sophos/Defender inventory, FortiGate/Palo estate, ingestion benchmarks).

_Last updated: 2026-06-17 · Branch: claud · Source: Architecture & Roadmap PDF v1_

---

## 1. Locked decisions

| Decision | Choice | Implication |
|---|---|---|
| Wazuh infrastructure | **Existing cluster** (separate) | Platform connects via NLB/API; we do NOT host Wazuh |
| Manager cluster | **2 managers** (1 master + 1 worker) | Quorum not required for managers; HA preserved |
| **3rd manager slot → AI node** | **Repurposed as our AI SOC host** (`m6i.2xlarge`) | AI runs on the instance that would've been manager #3 |
| Prior AI SOC instance | **Kept as reserve / standby** | 2nd triage worker or failover when queue backs up |
| AI model — primary | **3B** (`qwen2.5:3b-instruct`) | Fast triage on CPU, ~5–12s/alert |
| AI model — deep dive | **7B** (`qwen2.5:7b-instruct`) | Long-context / deeper investigation via queue |
| Inference hardware | **CPU-only** (`m6i.2xlarge`, 8 vCPU / 32 GB) | No GPU; small model + async queue + pre-reduction |
| AI triage scope | **Medium and up (rule level ≥ 7)** | Needs filtering + dedup before triage |
| Retention | **30 days hot + 90 days cold** | Indexer ISM (PDF: 30–45d indexed) + platform DB |
| Log filtering | **Basic now → Advanced over 60–90d** | The pre-reduction layer; controls cost AND AI load |
| Notification outputs | **Teams + Outlook + Jira** | per architecture diagram |

---

## 2. Real environment (from the briefing)

**Monitored sources ≈ 2,000**, but the mix matters more than the count — network
devices generate ~5× the data of a workstation.

| Layer | Inventory | Notes |
|---|---|---|
| Endpoints | **800–1,200 agents** (after full rollout) | Defender inventory = 2,002 devices; 215 Sophos (partial) |
| Servers | **~155** (105 Windows + 50 Linux) | higher per-device volume than workstations |
| Firewalls | **~404** (390 FortiGate 40F + 14 Palo Alto: 10× PA-220, 4× PA-820) | syslog |
| Switches / wireless | **~390 FortiSwitch 124E** + Cisco/Aruba | syslog — high noise, heavy filtering candidate |
| Cloud / EDR | Sophos, Defender, Entra (Azure AD) | Sophos Data Lake alone = 222 GB/30d (partial) |

> Earlier assumption of "1,400 endpoints + 800 firewalls" is **superseded**:
> ~800–1,200 endpoints/servers + ~800 **network devices** (mostly switches +
> ~404 firewalls).

### Ingestion (the number we were waiting for)

| Source | Realistic /month |
|---|---|
| Endpoints | 80–150 GB |
| Servers | 100–200 GB |
| Network devices | **300–800 GB** (dominant) |
| **Total (Basic filtering)** | **500 GB – 1 TB/month** |
| Advanced filtering target | 200–400 GB/month |
| No filtering (avoid) | 1.0–1.5 TB/month |

---

## 3. Final topology (2 managers + AI node + reserve)

```
        Outlook (notify)   Teams (notify)   Jira (alerting/events)
              ▲                  ▲                  ▲
              └──────────────────┴──────────────────┘
                                 │  (from AI SOC platform)
 ┌─────────────────────────── AWS us-east-1 (2 AZ, private subnets) ───────────────────────────┐
 │                                                                                              │
 │   INDEXER CLUSTER (critical)            MANAGER CLUSTER (HA)         AI SOC NODE (ours)       │
 │   3× r6i.2xlarge, 1.5 TB gp3            2× m6i.2xlarge               1× m6i.2xlarge           │
 │   quorum-safe, memory-optimized        (master + worker)            (was "manager #3")       │
 │            ▲                                  ▲                       Ollama: 3b + 7b +       │
 │            │ filebeat                         │ cluster               nomic-embed            │
 │            └──────────────────────────────────┤                      api · workers · pg ·    │
 │                                               │                      redis · dashboard      │
 │   DASHBOARD 1× m6i.large (ALB)                │                          ▲                   │
 │   GATEWAY 2× c6i.large (behind NLB)           │      reads indexer + manager API ── via NLB  │
 │                       ▲                       │                                              │
 └───────────────────────┼───────────────────────┼──────────────────────────────────────────-─┘
                          │ NLB (agents/syslog)   │
        Endpoints (agent) · Servers (agent) · Network devices (syslog: Forti/Palo)

   RESERVE: prior AI SOC instance — standby 2nd triage worker / failover
```

**Attach points:** AI node reads alerts from the **indexer** (`WAZUH_INDEXER_URL`
→ 3-node cluster via NLB) and calls the **manager API** (`WAZUH_API_URL` → gateways
behind NLB). Use NLB endpoints (not individual nodes) + a least-privilege
read-only service account.

> **HA note:** dropping managers 3→2 is safe — Wazuh manager clustering does not
> need an odd-quorum; the **indexer** is the tier that requires 3 nodes. So the AI
> node inherits the 3rd `m6i.2xlarge` without weakening the SIEM.

---

## 4. The funnel — filtering is layer 0 of AI feasibility

```
 sources ─► FILTER (gateway+rules) ─► Wazuh alerts ─► level≥7 ─► dedup+correlate ─► AI triage
            drop allow/session/                       funnel tip   unique incidents   3B → 7B
            keepalive/bulk-process                                                    (CPU)
```

The PDF's **layered filtering** (drop session start/end, normal allows, routine
DNS, web-filter allows, keepalives, repetitive switch events, duplicate
Sophos/Defender telemetry, bulk process/socket logs) is exactly the pre-reduction
our CPU-only AI requires. Keep VPN auth, admin logins, IPS/IDS, malware/high-sev,
policy/config changes, HA failover, WAN deny, Windows security events.

**Filtering roadmap:** start **Basic** (400–700 GB/mo) day one → tune to
**Advanced** (200–400 GB/mo) over 60–90 days. Layers 1–2 (source + gateway) cut
ingestion; layer 3 (Wazuh rules) cuts alert noise — see
[MONITORING-RULES.md](MONITORING-RULES.md).

---

## 5. AI node capacity (CPU-only, level ≥ 7)

### Host
- **Primary:** the repurposed manager #3 — `m6i.2xlarge` (8 vCPU / 32 GB). 32 GB
  holds `qwen2.5:3b-instruct` + `qwen2.5:7b-instruct` + `nomic-embed-text`
  resident at once.
- **Reserve:** prior AI SOC instance — bring online as a 2nd triage worker when
  `soc_agent_queue_depth` sustains high, or as failover.
- No AMX on m6i (that's c7i) → slightly lower tok/s than the PDF's c7i.2xlarge
  suggestion, but more RAM. Acceptable; measure in Phase 1.

### Throughput (per node, CPU Q4)
| Model | ~tok/s | ~sec/triage | ~triages/day |
|---|---|---|---|
| 3B primary | ~12–22 (m6i, no AMX) | ~7–14 | ~4,000–8,000 |
| 7B deep dive | ~5–9 | ~25–45 | ~1,200–2,500 |

### Sizing rule
```
3B workers = ceil( daily unique level≥7 incidents / 6,000 )
7B workers = ceil( daily escalations / 1,500 )
```
⏳ **Still to measure:** real level-≥7 incident rate after Basic filtering + dedup.
The reserve node covers the gap if one m6i.2xlarge isn't enough. The PDF's noise-
reduction AI use case (keep/drop/downgrade) further shrinks what reaches triage.

---

## 6. Model strategy (reconciled with the PDF)

PDF recommended **Llama 3 8B** as a starting single model. Our decision —
**3B primary / 7B deep** — is better for CPU: the 3B handles ~90% of level-≥7
alerts fast, the 7B (≈ the 8B tier) only fires on complex/critical cases via the
queue. Tiered routing (`llm_tier_strategy=auto`) already does this split.

| Setting | Value |
|---|---|
| `ollama_fast_model` / `llm_tier_fast_model` | `qwen2.5:3b-instruct` |
| `ollama_model` / `llm_tier_full_model` | `qwen2.5:7b-instruct` |
| `embedding_model` | `nomic-embed-text` (PDF alt: `bge-base-en`, `all-MiniLM-L6-v2`) |

Alternatives if benchmarking favors them: Llama 3 8B, Mistral 7B for the deep tier.
Ollama CPU tuning: `OLLAMA_KEEP_ALIVE=-1`, `OLLAMA_NUM_PARALLEL=2`,
`OLLAMA_NUM_THREAD=8`. Pre-pull all three models on first boot.

---

## 7. AI use cases (from briefing Ch.6 — goal: cut L1/L2 load 50–70%)

| Use case | Our handler | Status |
|---|---|---|
| Alert triage (risk score, cause, actions) | `triage` | have |
| Noise reduction (keep/drop/downgrade in real time) | new pre-triage stage | **add** — also cuts storage |
| Investigation assistant (NL Q&A, MITRE map) | `investigation` + MCP | gap |
| Auto incident summary (timeline, assets) | `reporting` + evidence pack | partial |
| Auto response (disable user, isolate, block IP) | `soar_run` behind `policy_guard` | **HITL only** |

> Briefing is explicit: **human-in-the-loop before any autonomous response.**
> Matches our autonomy-ladder plan — keep `soar_run` gated.

---

## 8. Retention — 30 hot / 90 cold

- **Indexer (their cluster):** ISM on `wazuh-alerts-*` — hot 0–30d (replicas=1),
  cold/snapshot 30–90d, delete >90d (PDF baseline: 30–45d indexed). See
  [BACKUP-RESTORE.md §2c](BACKUP-RESTORE.md).
- **Platform DB:** alerts 30d · triage results 90d · **cases/incidents ≥ 1yr** ·
  reports 90d · metering 365d.

---

## 9. Integrations

Feed **Wazuh** (manager wodles / syslog); platform reads resulting alerts and
sends outputs.

| Source/Sink | Path | Platform role |
|---|---|---|
| FortiGate / Palo Alto | syslog → gateway → manager `<remote>` | triage filtered firewall alerts |
| Sophos / Defender (EDR) | data lake / Defender ingest | triage endpoint alerts; dedup overlap |
| Entra (Azure AD) / O365 / MS Graph | Wazuh azure/office365 wodles | triage sign-in/audit alerts |
| AWS CloudTrail | Wazuh `aws-s3` wodle | triage cloud alerts |
| **Teams** | webhook | notifications |
| **Outlook / email** | SMTP connector | notifications |
| **Jira** | API (`jira_url` in config) | alerting / case-as-ticket |

> Move all integration secrets to secure handling — [INTEGRATIONS-HEALTH.md §7](INTEGRATIONS-HEALTH.md).

---

## 10. Rollout (aligned with briefing's phased model)

1. **Connect** — AI node → Wazuh NLB (indexer + API), read-only account; alerts → `triage_queue`.
2. **Filter** — Basic filtering at gateway/source; confirm 400–700 GB/mo.
3. **Reduce** — dedup + correlation + noise-reduction stage before triage.
4. **Triage (3B)** — level ≥ 7; tune noisy rules; measure incident rate.
5. **Deep dive (7B)** — escalate ambiguous/critical.
6. **Scale** — add the reserve node as a 2nd worker if queue depth sustains.
7. **Tune to Advanced filtering** over 60–90 days → 200–400 GB/mo.
8. **Retention + dashboards + ops scripts** — 30/90 ISM, [DASHBOARDS.md](DASHBOARDS.md), health/capacity crons.

---

## 11. Open items

- [ ] Measure level-≥7 incident rate after Basic filtering → confirm 1 vs 2 AI nodes
- [ ] Confirm m6i.2xlarge CPU throughput meets the rate (else use reserve / consider c7i)
- [ ] Platform DB EBS sizing from measured triage/case volume
- [ ] Wire Jira connector as case-ticket sink (config present, integration TBD)
- [ ] Network path: AI node → Wazuh NLB (security groups, private subnets, 2 AZ)
- [ ] Decide optional hybrid API escalation tier vs fully local
- [ ] Build noise-reduction pre-triage stage (keep/drop/downgrade)

---

### Related
[BACKUP-RESTORE.md](BACKUP-RESTORE.md) · [MONITORING-RULES.md](MONITORING-RULES.md) · [DASHBOARDS.md](DASHBOARDS.md) · [INTEGRATIONS-HEALTH.md](INTEGRATIONS-HEALTH.md)
