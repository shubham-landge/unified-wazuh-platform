# Production Deployment & Capacity Plan — Payless SOC

Scale-out plan for the autonomous SOC platform layered on the existing Wazuh
cluster. Captures the locked decisions, the EPS funnel, the CPU-only AI sizing,
retention, and integration. Some sizing is **provisional pending the full
architecture PDF** (firewall logging mode / EPS) — marked ⏳ below.

_Last updated: 2026-06-17 · Branch: claud_

---

## 1. Locked decisions

| Decision | Choice | Implication |
|---|---|---|
| Wazuh infrastructure | **Already deployed** (separate cluster) | Our platform connects to it; we do NOT host Wazuh |
| AI model — primary | **3B** (qwen2.5:3b-instruct) | Fast triage on CPU, ~5–12s/alert |
| AI model — deep dive | **7B** (qwen2.5:7b-instruct) | Long-context / deeper investigation via queue |
| Inference hardware | **CPU-only EC2** | No GPU; small model + async queue + pre-reduction |
| AI triage scope | **Medium and up (rule level ≥ 7)** | Broader → needs pre-reduction + scalable workers |
| Retention | **30 days hot + 90 days cold** | Indexer ISM policy + platform DB retention |
| Firewall logging mode | ⏳ **Pending architecture PDF** | Dominant EPS driver — sizing provisional until known |

---

## 2. Existing Wazuh cluster (what we connect to)

```
            Agents (1,400)        Firewalls (800, syslog)      Cloud wodles
                 │                        │                  CloudTrail/O365/Graph
                 └───────────┬────────────┴───────────┬───────────────┘
                             ▼                         ▼
                    ┌──────────────────┐      2× NGINX gateway  ── behind NLB
                    │  Wazuh managers  │◄─────  (enrollment 1515 / API 55000)
                    │  2 active (+1 rsv)│
                    └────────┬─────────┘
                             ▼  filebeat
                    ┌──────────────────┐
                    │  Wazuh indexer   │   3-node OpenSearch cluster
                    │  (3 nodes)       │   stores wazuh-alerts-*
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │ Wazuh dashboard  │   1 node (OpenSearch Dashboards)
                    └──────────────────┘
```

**Our platform attaches at two points:** reads alerts from the **indexer**
(`WAZUH_INDEXER_URL` → the 3-node cluster / NLB), and calls the **manager API**
(`WAZUH_API_URL` → via the NGINX gateways / NLB) for agents, rules, groups.
Multi-manager/indexer is already supported in config (`wazuh_managers`,
`wazuh_indexers` — comma-separated).

> **Action:** point `WAZUH_INDEXER_URL` / `WAZUH_API_URL` at the NLB endpoints,
> not individual nodes, so failover is transparent. Use a read-only service
> account scoped to the indices/endpoints we need (least privilege).

---

## 3. EPS funnel — why CPU-only AI is feasible here

The platform never sees the raw firehose. Reduction happens in stages:

```
 Raw events  ──►  Wazuh rules  ──►  level ≥ 7 alerts  ──►  PRE-REDUCTION  ──►  AI triage
 ~6–17k EPS       (manager)         (the funnel tip)      dedup+correlate      (3B on CPU)
 ⏳ pending PDF                                            unique incidents     7B for deep
```

Provisional EPS (refine from the PDF):

| Source | Count | Est. EPS | Driver |
|---|---|---|---|
| Endpoints | 1,400 | ~400–700 | ~0.3 EPS/agent |
| Firewalls | 800 | ⏳ ~4,000–16,000 | **logging mode TBD** |
| CloudTrail + O365 + MS Graph | 3 | ~100–500 | bursty |
| **Total** | | **~6,000–17,000 EPS** | firewall-dominated |

**Critical design rule:** AI triages **unique incidents, not every level-≥7
alert.** Without pre-reduction, 800 firewalls at level ≥ 7 can produce tens of
thousands of near-duplicate alerts/day and starve the CPU queue. We already have
`alert_dedup_enabled` + `alert_correlation_window_minutes` — these MUST run
before the triage handler so identical/related alerts collapse into one AI call.

---

## 4. AI triage capacity (CPU-only, level ≥ 7)

### Pipeline
```
indexer alerts (level≥7) ─► poller ─► dedup ─► correlation/group ─► triage_queue
                                                                        │
                                          3B worker(s) ── BRPOP ────────┘
                                                │  verdict/severity/summary
                                          escalate? ─► 7B deep-investigation queue
```

### Throughput math (per worker, c7i.4xlarge class)
| Model | ~tok/s (CPU Q4) | ~sec/triage | ~triages/day/worker |
|---|---|---|---|
| 3B primary | ~20–35 | ~5–12 | ~5,000–10,000 |
| 7B deep dive | ~8–14 | ~20–40 | ~1,500–3,000 |

### Sizing rule
```
3B workers needed = ceil( daily unique level≥7 incidents / 7,000 )
7B workers needed = ceil( daily escalations / 2,000 )
```
⏳ Plug in the real level-≥7 incident count once the firewall EPS is known.
Provisional: if ~20–30k unique incidents/day after reduction → **3–4 primary
workers**; escalations (~5–10%) → **1 deep-dive worker**.

### Instance recommendation for the AI/platform node(s)
- **Start:** your current `m7i.2xlarge` runs the 3B + platform for early rollout.
- **Production at level ≥ 7:** move the inference+worker tier to **`c7i.4xlarge`
  (Intel AMX) or `c7g.4xlarge` (Graviton)** — ~2× the CPU tok/s. Run N triage
  worker replicas against one Ollama, or scale to a 2nd node.
- Keep **API + Postgres + Redis + dashboard** on a small separate node
  (`m7i.large`/`c7i.large`) so inference load can't starve the control plane.

---

## 5. Model & inference configuration

Locked: **3B primary / 7B deep**, instruct variants (security reasoning, not code).

| Setting | Value | Was |
|---|---|---|
| `ollama_fast_model` (primary) | `qwen2.5:3b-instruct` | qwen2.5-coder:3b |
| `ollama_model` (deep dive) | `qwen2.5:7b-instruct` | qwen2.5-coder:7b |
| `llm_tier_fast_model` | `qwen2.5:3b-instruct` | qwen2.5-coder:3b |
| `llm_tier_full_model` | `qwen2.5:7b-instruct` | qwen2.5-coder:7b |
| `llm_tier_strategy` | `auto` (default 3B; escalate to 7B on level/technique) | — |
| `embedding_model` | `nomic-embed-text` | unchanged |

### Ollama CPU tuning (env)
```
OLLAMA_KEEP_ALIVE=-1        # keep models resident — no reload per alert
OLLAMA_NUM_PARALLEL=2       # low; CPU is memory-bandwidth bound
OLLAMA_NUM_THREAD=<physical cores>   # 8 on c7i.4xlarge
```
Pre-pull `qwen2.5:3b-instruct`, `qwen2.5:7b-instruct`, `nomic-embed-text` on first
boot (bake into the AMI / EBS volume for air-gapped).

---

## 6. Retention plan — 30 days hot / 90 days cold

### Wazuh indexer (their cluster) — ISM policy on `wazuh-alerts-*`
| Phase | Age | Action |
|---|---|---|
| Hot | 0–30 d | active writes, full search, replicas=1 |
| Cold / snapshot | 30–90 d | searchable snapshot or warm tier; force-merge |
| Delete | > 90 d | drop index (snapshot must exist first) |

Implement via OpenSearch ISM (see [BACKUP-RESTORE.md §2c](BACKUP-RESTORE.md)).
3-node cluster → keep replicas=1 in hot for HA.

### Platform PostgreSQL (our side)
| Data | Retention | Note |
|---|---|---|
| Alerts (mirror/index) | 30 d | align with indexer hot; we don't duplicate cold |
| Triage results | 90 d | keep through the cold window for audit |
| **Cases / incidents** | **keep ≥ 1 yr** | incidents outlive raw logs (investigation record) |
| Reports | `report_retention_days=90` | unchanged |
| Metering | `metering_retention_days=365` | unchanged |

> ⏳ Storage GB depends on level-≥7 alert volume (PDF). Size the platform DB EBS
> from real triage counts; the indexer storage is the Wazuh team's sizing.

---

## 7. Integration plan (cloud sources)

These feed **Wazuh** (manager wodles), and our platform reads the resulting
alerts. Verification steps live in [INTEGRATIONS-HEALTH.md](INTEGRATIONS-HEALTH.md).

| Source | Ingest path | Our platform role |
|---|---|---|
| AWS CloudTrail | Wazuh `aws-s3` wodle → manager → indexer | triage + correlate CloudTrail alerts |
| O365 | Wazuh `office365` wodle | triage sign-in/audit/DLP alerts |
| MS Graph | Wazuh Azure/Graph module | triage security/audit events |
| Firewalls (800) | syslog → manager `<remote>` | ⏳ dominant volume — confirm mode in PDF |

> Move every integration secret (Graph client secret, AWS keys, O365 creds,
> webhooks) into secure handling — [INTEGRATIONS-HEALTH.md §7](INTEGRATIONS-HEALTH.md).

---

## 8. Rollout phases

1. **Connect** — point platform at the Wazuh NLB endpoints (indexer + API),
   read-only service account; confirm alerts flow into `triage_queue`.
2. **Reduce** — enable dedup + correlation BEFORE triage; verify unique-incident
   rate is within CPU budget (watch `soc_agent_queue_depth`).
3. **Triage (3B)** — level ≥ 7 on the 3B model; tune noisy rules
   ([MONITORING-RULES.md](MONITORING-RULES.md)) to cut volume.
4. **Deep dive (7B)** — escalate ambiguous/critical to the 7B queue.
5. **Scale** — add triage worker replicas / move to c7i|c7g once real level-≥7
   volume is measured.
6. **Retention** — apply 30/90 ISM on indexer + platform DB retention jobs.
7. **Dashboards & ops** — stand up the [DASHBOARDS.md](DASHBOARDS.md) set; schedule
   `daily-health-check.sh` + `weekly-capacity-report.sh`.

---

## 9. Open items ⏳ (resolve from the architecture PDF)

- [ ] Firewall logging mode (all-traffic vs deny/threat) → real total EPS
- [ ] Measured level-≥7 alert volume/day → final 3B/7B worker count + instance size
- [ ] Platform DB EBS sizing from triage/case volume
- [ ] Confirm cloud wodle EPS (CloudTrail/O365/Graph) and burst peaks
- [ ] Network path: platform node → Wazuh NLB (security groups, private subnets)
- [ ] Decide hybrid API escalation tier (optional overflow) vs fully local

---

### Related
[CPU inference tuning] · [BACKUP-RESTORE.md](BACKUP-RESTORE.md) · [MONITORING-RULES.md](MONITORING-RULES.md) · [DASHBOARDS.md](DASHBOARDS.md) · [INTEGRATIONS-HEALTH.md](INTEGRATIONS-HEALTH.md)
