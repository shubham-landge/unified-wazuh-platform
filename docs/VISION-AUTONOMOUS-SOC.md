# Vision: The Autonomous SOC

> **Status**: North-star architecture document.  
> **Updated**: 2026-06-17  
> **Scope**: Describes where the Unified Wazuh SOC Platform is heading, the trust model that gets it there, and the build sequence to close the remaining gaps.

---

## 1. Reframe the goal honestly

"No SOC team" is not a switch you flip — it is a **trust ladder**, exactly like autonomous driving levels (L0 → L5). You earn autonomy *per function* by proving accuracy. The platform moves an organization from **L0 (full manual team)** to **L4 (a small governance function)**. Selling "fire your whole security team" fails at procurement and at the first incident with legal exposure; selling **"10x your existing people, lights-out for routine work"** is true and buyable. The end state still has *someone* accountable — it just is not a 24/7 ops team.

### Autonomy ladder

| Level | Name | What the platform does | Human role | Example |
|-------|------|------------------------|------------|---------|
| L0 | Manual | Wazuh alerts appear; humans triage everything | Full analyst team | Baseline Wazuh only |
| L1 | Assisted | AI writes summaries and recommended actions; humans decide | Analyst reviews every output | Current triage mode |
| L2 | Supervised | AI routes, correlates, drafts playbooks; humans approve writes | Analyst approves cases and response | `policy_guard` with `approval` autonomy |
| L3 | Conditional | AI runs read-only enrichment and low-risk response automatically; humans handle exceptions | Exception handling + quality review | `autonomy_level=full` on safe read-only agents |
| L4 | Lights-out | AI handles routine detection, triage, enrichment, and response end-to-end; humans govern policy and novel threats | Governance + red team + legal sign-off | Mature production deployment |
| L5 | Full autonomy | Theoretically unsupervised; not pursued for security accountability reasons | Oversight only | **Out of scope** |

The ladder is **per function**, not global. Correlation may reach L4 before response actions reach L2. The product exposes this as a first-class setting: every agent/action has a risk class and a proven accuracy score; the org sets the autonomy threshold per function and watches it climb as accuracy data accumulates.

---

## 2. The Snowflake lesson

Snowflake won on three platform properties. They translate directly to a security platform:

1. **One security API over any tool** — the MCP/connector layer is the equivalent of "SQL over any storage." This is why the empty `integrations/wazuh_mcp/` gap matters strategically, not just technically. Make Wazuh *a* source, not *the* product, so CrowdStrike, Sentinel, Suricata, cloud CSPM, etc. plug in without re-architecting.
2. **Self-managing, self-tuning** — the system must reduce its own noise, expand its own detection coverage, and refine its own prompts. Without this it is a chatbot over Wazuh that still needs engineers. This is the `SkillOpt` + feedback-loop + detection-as-code work, and it is the real moat.
3. **Governance plane = the unlock for L4.** The jump to lights-out is gated by **trust, not AI capability**: policy-guard before any write action, full audit trail, explainable decisions, hard guardrails, approval gates that shrink as confidence grows. Most teams over-invest in agent cleverness and under-invest here.

---

## 3. Target architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENTS                                         │
│  Dashboard │ REST API │ MCP (Claude/Cursor) │ SOAR playbooks │ Ticketing    │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
┌─────────────────────────────────────────────────────────────────────────────┐
│                         UNIFIED SECURITY API                                 │
│  Auth / Tenant / Rate limit / Audit / Metering / Approval / Policy guard     │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AGENT ORCHESTRATION                                  │
│  correlation │ triage │ response_planner │ policy_guard │ evidence_pack     │
│  ti_enrich │ ueba_check │ soar_run │ case_create │ notify │ review │ lead  │
│  autonomy_level per agent: read-only │ approval │ full                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SELF-LEARNING + RAG                                  │
│  skill_memory → few_shot.retrieve → prompts                                  │
│  feedback_loop → prompt_refiner → SkillOpt → best_skill.md                   │
│  meta_agent → missed-detection scan → detection backlog                      │
│  knowledge_chunks ← ATT&CK skill DB + Sigma rules + docs                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CONNECTOR FABRIC                                     │
│  Wazuh API │ Wazuh Indexer │ Sigma │ OSINT (Maigret) │ TI feeds │ HIBP      │
│  Jira │ ServiceNow │ Email │ Slack │ Teams │ PagerDuty │ Cloud APIs         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Three priorities over everything else

### 4.1 Build the autonomy ladder into the product as a first-class concept
Every agent action carries:
- `risk_class`: `read`, `write-low`, `write-high`, `destructive`
- `confidence`: historical accuracy of this agent on this alert class
- `autonomy_level`: `read-only` → `approval` → `full`

The platform blocks or escalates based on the intersection. This is both the differentiator and the safety story. `shared/orchestrator/handlers.py::policy_guard()` already implements the gate; the next step is to persist per-agent accuracy scores and expose them in the UI.

### 4.2 Make the self-learning loop the heart, not a feature
The compounding asset is the decision history: every analyst correction, every confirmed verdict. That history becomes a data network effect across tenants — a moat no single Wazuh deployment can match. The loop:

1. `skill_memory.add_experience(task)` stores completed agent runs.
2. `shared/rag/few_shot.retrieve()` returns top-K similar past runs.
3. `feedback_worker` records analyst thumbs up/down and corrections.
4. `services/worker/app/prompt_refiner.py` (planned) proposes prompt edits.
5. A policy-guarded promotion step updates `best_skill.md` / prompt templates.

See [SKILL-OPT.md](SKILL-OPT.md) for the detailed design.

### 4.3 Treat governance/explainability as the product, not compliance overhead
"Why did the system block this?" must be answerable in one click with an evidence pack. Every write action must produce:
- The triggering alert(s)
- The triage result and confidence
- The policy-guard decision rationale
- The enrichment/timeline
- The exact action taken and its outcome

`shared/orchestrator/handlers.py::evidence_pack()` already generates this bundle.

---

## 5. What honestly stays human

Design for these to stay human-led; do not pretend them away:

| Function | Why it stays human | How the platform supports it |
|----------|--------------------|------------------------------|
| Accountability / legal liability | Someone must be accountable for automated decisions | Approval audit trail, policy-guard, role-based sign-off |
| Business-context risk acceptance | Only the business can accept residual risk | Risk scoring + evidence packs + approval workflows |
| Regulatory sign-off | Compliance frameworks require accountable owners | Compliance dashboards + exception workflows |
| Novel / targeted-adversary judgment | AI fails on never-before-seen TTPs | Human escalation path + red-team integration |
| Red team / adversary simulation | Offensive testing of the platform itself | Scheduled red-team exercises + chaos tooling |

Position these as the **oversight function the platform serves** — not work it eliminates.

---

## 6. Concrete build sequence

| Wave | Deliverable | Files / gaps | Business outcome |
|------|-------------|--------------|------------------|
| 1 | MCP / abstraction layer | `services/mcp/server.py` → real FastMCP; `integrations/wazuh_mcp/` | SOC queryable from Claude Desktop / Cursor; tool-agnostic foundation |
| 2 | Self-learning loop | `services/worker/app/prompt_refiner.py`, `shared/rag/skill_memory.py` | Accuracy improves without engineering; compounding moat |
| 3 | ATT&CK skill import | Seed `knowledge_chunks` from `mukul975/awesome-attck-skill-db` | Few-shot and RAG answers improve dramatically |
| 4 | Detection engineering automation | `services/worker/app/sigma_worker.py` + Sentinel → Sigma pipeline | Expands coverage automatically |
| 5 | Governance / L4 hardening | Per-agent accuracy scoring, policy analytics, approval heatmap | Procurement-ready trust model |

The widget's "Priority plan" tab lays out the same waves. **Wave 1 (MCP server)** is the highest-leverage starting point because it is the foundation that lets every later capability plug in tool-agnostically — the "SQL over any storage" moment.

---

## 7. Current implementation status

Implemented on `main`:
- `policy_guard`, `correlation`, `response_planner`, `evidence_pack` handlers
- `AgentDefinition.autonomy_level`
- `shared/rag/few_shot.py` retrieval
- `services/mcp/server.py` (HTTP shim; upgrade to FastMCP in Wave 1)
- `shared/connectors/circuit_breaker.py`
- Prompt-injection sanitization in `shared/connectors/llm_provider.py`

Still open:
- `services/worker/app/prompt_refiner.py` — SkillOpt prompt refinement
- ATT&CK skill DB import — see [ATTACK-RAG-IMPORT.md](ATTACK-RAG-IMPORT.md)
- Sentinel detections → Sigma pipeline
- Maigret container wiring — see `services/worker/app/osint_worker.py`
- Prompt-injection guard model (HuggingFace `rogue-security/prompt-injection-jailbreak-sentinel-v2`) as a pre-filter

---

## 8. Related documents

- [UNIFIED-ARCHITECTURE.md](UNIFIED-ARCHITECTURE.md) — current deployment architecture
- [SKILL-OPT.md](SKILL-OPT.md) — self-learning loop design
- [ATTACK-RAG-IMPORT.md](ATTACK-RAG-IMPORT.md) — importing 754 ATT&CK-mapped skills
- [AI-MODEL-REVIEW.md](AI-MODEL-REVIEW.md) — recommended local and cloud LLMs
- [MULTI-TOOL-PLAN.md](MULTI-TOOL-PLAN.md) — parallel tool ownership and contracts
