# Phase 9 — Detection Beyond the Endpoint

Implements the modern-SOC principles from Unit 42's
[The 72-Minute Race](https://unit42.paloaltonetworks.com/soc-72-minute-race/) and
[Detection Beyond the Endpoint](https://unit42.paloaltonetworks.com/detection-beyond-the-endpoint/):
identity-first detection, cross-domain alert stitching, parallel enrichment, and
operationalized containment — all within the CPU-only constraint.

Builds on Phase 8 ([MULTI-TOOL-PLAN.md](MULTI-TOOL-PLAN.md)). Same conventions:
single-owner files, `dev` integration branch, STATUS.md updates, per-PR review.

> **Claude's role this phase = REVIEW & INTEGRATE ONLY.** Claude writes no
> implementation code. OpenCode, Codex, and Antigravity build; Claude reviews each
> PR against §6, resolves shared-file merges, registers routers, runs the suite,
> and merges `dev` → `main`.

---

## 0. Why (the five principles → our gaps)

| Principle (from the articles) | Our gap | Owner |
|---|---|---|
| Identity is the front door (65% of initial access) | No identity detections | Codex |
| Unified cross-domain incidents (alert stitching) | `AlertIncident` is endpoint-centric | OpenCode |
| Parallel auto-enrichment, not sequential | Enrichment not fanned out pre-LLM | OpenCode |
| Behavioral over static | UEBA exists but not primary | (Phase 8 / Antigravity) |
| Operationalized containment (72-min breakout) | No pre-defined identity/cloud playbooks | Codex + OpenCode |

**CPU-only stays intact:** entity extraction, stitching, ITDR scoring, and
enrichment are all cheap/non-LLM. The LLM still runs **only at the (now
cross-domain) incident level**, per the L0–L4 model in
[the analysis-pyramid discussion]. One LLM call now reasons over a whole kill
chain instead of one fragment.

---

## 1. Branch strategy & merge order

1. Tools rebase their `tool/<name>` branch onto fresh `dev` (currently == `main`).
2. Each builds only in its owned zone → PR into `dev`.
3. **Claude reviews** each PR (§6), merges, registers shared files.
4. `dev` → `main`, tag `v0.5.0`.

**Merge order (foundational first):**
```
1. OPENCODE   entity-stitching schema + engine        [everything depends on entities/incidents]
2. CODEX      identity connectors + ITDR worker        [emits alerts that get stitched]
3. OPENCODE   parallel enrichment + evidence pack + kill-chain stage
4. ANTIGRAVITY coverage dashboard + kill-chain UI + SLA/breakout metrics
5. CODEX+OPENCODE containment playbooks (gated by policy_guard + approvals)
6. CLAUDE     dev → main, tag v0.5.0
```

---

## 2. Schema (OpenCode owns; Claude reviews migration)

New tables + model fields. Add to `database/schema.sql` and `shared/models/`.

```sql
-- Normalized entities extracted from every alert (cheap, no LLM).
CREATE TABLE entities (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL,
    entity_type  VARCHAR(24) NOT NULL,   -- user | host | ip | principal | session | device
    value        VARCHAR(512) NOT NULL,  -- normalized (lowercased UPN, canonical IP, ARN, ...)
    risk_score   NUMERIC(5,2) DEFAULT 0,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata     JSONB DEFAULT '{}',
    UNIQUE (tenant_id, entity_type, value)
);
CREATE INDEX ix_entities_tenant_type_value ON entities (tenant_id, entity_type, value);

-- Which entities appear in which alert, and in what role.
CREATE TABLE alert_entities (
    alert_id   UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    entity_id  UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    role       VARCHAR(16) NOT NULL DEFAULT 'observed',  -- actor | target | source | dest | observed
    PRIMARY KEY (alert_id, entity_id, role)
);

-- Which entities tie an incident together (the stitching backbone).
CREATE TABLE incident_entities (
    incident_id UUID NOT NULL REFERENCES alert_incidents(id) ON DELETE CASCADE,
    entity_id   UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, entity_id)
);
```

Extend `alert_incidents` (model `shared/models/alert_dedup.py::AlertIncident`):

```sql
ALTER TABLE alert_incidents ADD COLUMN cross_domain      BOOLEAN     DEFAULT false;
ALTER TABLE alert_incidents ADD COLUMN source_domains    JSONB       DEFAULT '[]';   -- ["endpoint","identity","cloud"]
ALTER TABLE alert_incidents ADD COLUMN kill_chain_stage  VARCHAR(24) DEFAULT 'unknown'; -- initial_access|priv_esc|lateral|exfil|...
ALTER TABLE alert_incidents ADD COLUMN stage_history     JSONB       DEFAULT '[]';
ALTER TABLE alert_incidents ADD COLUMN sla_due_at        TIMESTAMPTZ;
ALTER TABLE alert_incidents ADD COLUMN first_enriched_at TIMESTAMPTZ;
```

Extend `alerts` (model `shared/models/alert.py`) — Codex's identity worker populates these:

```sql
ALTER TABLE alerts ADD COLUMN source_type VARCHAR(24) DEFAULT 'endpoint'; -- endpoint|identity|cloud|network|saas
ALTER TABLE alerts ADD COLUMN principal   VARCHAR(512);  -- AWS ARN / cloud principal
ALTER TABLE alerts ADD COLUMN session_id  VARCHAR(256);
```

---

## 3. Integration contracts (build against these — stable)

| Contract | Signature / rule |
|---|---|
| Entity extraction | `shared/correlation/entities.py::extract_entities(alert) -> list[ExtractedEntity]` (OpenCode owns; pure, no LLM) |
| Identity alert emission | Codex's `identity_worker` writes `Alert` rows with `source_type="identity"`, `user` (UPN, lowercased), and `principal`/`session_id` where available — so the extractor stitches them. **No schema drift.** |
| Stitching | `shared/correlation/stitch.py::stitch_incident(session, alert, tenant_id) -> AlertIncident` (supersedes the old endpoint-only dedup grouping; preserves `noise_reduction.evaluate` call site) |
| Enrichment fan-out | `shared/orchestrator/enrichment.py::enrich_incident(incident) -> EvidencePack` (async, `asyncio.gather`) |
| Coverage data | Antigravity reads connected sources from a `source_registry` + MITRE mapping; no new writes to others' tables |
| New router | expose `router = APIRouter(...)`; **Claude registers in `main.py`** |
| New config | request in PR description; **Claude adds to `config.py`** |

---

## 4. Per-tool briefs (self-contained — paste to each tool)

### 🟩 OPENCODE — Correlation, stitching, enrichment, kill-chain

```
Repo: shubham-landge/unified-wazuh-platform. Read docs/PHASE-9-DETECTION-BEYOND-ENDPOINT.md §2,§3.
SETUP: git fetch origin && git checkout tool/opencode && git rebase origin/dev

OWNED ZONE (exclusive):
- shared/correlation/  (NEW: entities.py, stitch.py, killchain.py)
- shared/orchestrator/enrichment.py  (NEW)
- shared/models/entity.py  (NEW), shared/models/alert_dedup.py  (extend AlertIncident)
- shared/orchestrator/handlers.py  (correlation handler becomes the stitcher)

TASKS:
1. extract_entities(alert) -> list[ExtractedEntity]: pull user/host/ip/principal/
   session/device from any alert (endpoint, identity, cloud, network). Normalize
   (lowercase UPN, canonical IP). Pure function, no LLM.
2. stitch_incident(session, alert, tenant_id): within a 2-6h window, link alerts
   that share an entity into ONE AlertIncident — regardless of source_type. Set
   cross_domain + source_domains. Persist entities, alert_entities, incident_entities.
   MUST preserve the existing noise_reduction.evaluate() call site/order.
3. killchain.py: compute kill_chain_stage from members' MITRE tactics; append to
   stage_history when it advances. Flag incidents that are ADVANCING.
4. enrich_incident(incident) -> EvidencePack: asyncio.gather over TI, asset
   criticality, user-risk, geo, UEBA, related past incidents (RAG few_shot.retrieve).
   Set first_enriched_at. Assemble the evidence pack BEFORE the triage LLM call.
5. Wire the assembled EvidencePack into the incident-level triage path.

DO NOT TOUCH: connectors, dashboard, mcp, config.py, docker-compose, main.py.
Need a config field / schema migration reviewed? List it in the PR.
TESTS: tests/test_entity_stitching.py, tests/test_killchain.py, tests/test_enrichment.py
DoD: pytest -q green; only owned files changed; PR into dev.
```

### 🟦 CODEX — Identity connectors, ITDR worker, containment actions

```
Repo: shubham-landge/unified-wazuh-platform. Read docs/PHASE-9-DETECTION-BEYOND-ENDPOINT.md §3.
SETUP: git fetch origin && git checkout tool/codex && git rebase origin/dev

OWNED ZONE:
- shared/connectors/  (NEW: entra.py, o365.py, msgraph.py, cloudtrail.py)
- services/worker/app/identity_worker.py  (NEW)
- shared/soar/actions_identity.py  (NEW: containment actions)

TASKS:
1. Identity/cloud connectors: Entra ID sign-in + audit logs, O365/Exchange,
   MS Graph (risky users/sign-ins, OAuth grants), AWS CloudTrail. Read-only ingest.
2. identity_worker.py — score events for the 7 ITDR detections and emit Alert rows
   with source_type="identity", user=<UPN lowercased>, principal/session_id set:
     impossible_travel, mfa_fatigue, risky_signin, illicit_oauth_consent,
     privilege_change, helpdesk_impersonation (reset+MFA re-register), dormant_reactivation
   CONTRACT: emit standard Alert rows — OpenCode's extract_entities() stitches them.
   Do NOT implement stitching yourself.
3. Containment actions (shared/soar/actions_identity.py): disable_user,
   revoke_sessions, revoke_oauth_tokens, force_reauth, block_ip. Pure action
   functions — OpenCode/policy_guard decides WHEN to call them (gated by autonomy
   + approvals). Each action returns a structured result; never auto-fire.

DO NOT TOUCH: shared/correlation, shared/orchestrator, dashboard, config.py,
docker-compose, main.py. Request config fields (graph creds, etc.) in the PR.
TESTS: tests/test_identity_worker.py, tests/test_entra_connector.py, tests/test_identity_actions.py
DoD: pytest -q green; only owned files; PR into dev.
```

### 🟨 ANTIGRAVITY — Coverage map, kill-chain UI, speed metrics

```
Repo: shubham-landge/unified-wazuh-platform. Read docs/PHASE-9-DETECTION-BEYOND-ENDPOINT.md §3.
SETUP: git fetch origin && git checkout tool/antigravity && git rebase origin/dev

OWNED ZONE:
- services/dashboard/  (templates, static)
- services/api/app/routers/metrics.py  (APPEND gauges only — module-level, never per-request)
- shared/source_registry.py  (NEW: registry of connected data sources + MITRE coverage)

TASKS:
1. Detection coverage dashboard: data-source x MITRE-tactic heatmap from
   shared/source_registry.py — show connected sources and blind spots (the "10 IT zones").
2. Kill-chain stage visualization on the incident/case view: render
   AlertIncident.kill_chain_stage + stage_history as a progression bar; highlight
   ADVANCING incidents (cross_domain=true, stage moving toward exfil).
3. Speed metrics in metrics.py (module-level gauges, set() in handler):
   soc_incident_mttd_seconds, soc_incident_mttr_seconds, soc_time_to_full_enrichment_seconds,
   soc_breakout_incidents_total (incidents that reached lateral/exfil).
4. SLA timer display: incident.sla_due_at countdown on the dashboard.

DO NOT TOUCH: correlation, connectors, orchestrator, identity_worker, config.py,
main.py (beyond metrics router which is already registered). Need triage_worker to
write a Redis metric? List it in the PR — Claude wires the producer side.
TESTS: tests/test_source_registry.py, tests/test_coverage_metrics.py
DoD: pytest -q green; only owned files; PR into dev.
```

---

## 5. File ownership matrix

| Zone | Owner |
|---|---|
| `shared/correlation/` (entities, stitch, killchain) | OpenCode |
| `shared/orchestrator/enrichment.py`, handlers | OpenCode |
| `shared/models/entity.py`, `alert_dedup.py` (incident extend) | OpenCode |
| `shared/models/alert.py` (source_type/principal/session_id fields) | OpenCode (request; Claude reviews) |
| `shared/connectors/` (entra/o365/msgraph/cloudtrail) | Codex |
| `services/worker/app/identity_worker.py` | Codex |
| `shared/soar/actions_identity.py` | Codex |
| `services/dashboard/`, `shared/source_registry.py` | Antigravity |
| `routers/metrics.py` (append gauges) | Antigravity |
| `database/schema.sql` | OpenCode writes; **Claude reviews** |
| `config.py`, `docker-compose*.yml`, `main.py`, `requirements.txt` | **Claude-merged** |
| `tests/` | per-tool, separate files |

---

## 6. Claude review checklist (per incoming PR)

- [ ] `python -m pytest -q` green on the rebased branch
- [ ] Only files in the tool's owned zone changed (shared-file asks listed in PR)
- [ ] Integration contracts honored (§3): `extract_entities`, identity-alert emission
      schema, `stitch_incident`, `enrich_incident`, coverage data — **no signature drift**
- [ ] No changes to other tools' exclusive zones
- [ ] Schema migration is additive and reversible; indexes present
- [ ] Containment actions never auto-fire — gated by policy_guard + approvals
- [ ] New code matches surrounding patterns (async, types, logging)
- [ ] New tests for new modules; STATUS.md updated
- [ ] CPU-only respected — no new per-alert LLM calls

### Claude merge actions (integrator only)
1. Run full suite after each merge into `dev`.
2. Register any new routers in `main.py`; add requested config fields to `config.py`/`.env.example`.
3. Add any new connector creds to `docker-compose*.yml` env if needed.
4. `dev` → `main`, tag `v0.5.0`, push.

## 7. Definition of done (phase)

- [ ] All tool branches merged to `dev`, then `dev` → `main` tagged `v0.5.0`
- [ ] Cross-domain incidents form (endpoint + identity + cloud stitched by shared entity)
- [ ] 7 ITDR detections emitting; identity is a first-class source_type
- [ ] Enrichment fan-out populates evidence pack before the LLM (parallel, not sequential)
- [ ] Kill-chain stage + SLA timers visible; coverage heatmap renders
- [ ] Containment playbooks present, gated, never auto-firing
- [ ] Full suite green; no regression (323+ tests)

---

### Related
[MULTI-TOOL-PLAN.md](MULTI-TOOL-PLAN.md) · [PARALLEL-WORKFLOW.md](PARALLEL-WORKFLOW.md) · [operations/DEPLOYMENT-PLAN.md](operations/DEPLOYMENT-PLAN.md)
