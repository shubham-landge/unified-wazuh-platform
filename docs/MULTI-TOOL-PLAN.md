# Multi-Tool Build Plan — Remaining Work (Phase 7)

Coordination plan for **Claude, Codex, OpenCode, and Antigravity** working the
remaining backlog in parallel without merge conflicts. Supersedes the initial
[PARALLEL-WORKFLOW.md](PARALLEL-WORKFLOW.md) (that covered the first build, now
done) and keeps its conventions: **single-owner files, `dev` integration branch,
STATUS.md updates, Claude as reviewer/integrator.**

_Created 2026-06-17 on `claud`. Reflects the locked deployment decisions in
[operations/DEPLOYMENT-PLAN.md](operations/DEPLOYMENT-PLAN.md)._

---

## 0. Current state

- `claud` is the most complete branch (this session's work: ops layer, deployment
  plan, 3B/7B model strategy, noise-reduction gate). **285 tests passing.**
- Tool branches (`tool/codex`, `tool/opencode`, `tool/antigravity`) are stale
  (~Jun 13) and **must rebase onto fresh `dev` before new work.**
- `integrations/wazuh_mcp/` is an empty directory (MCP gap).

### Branch strategy
1. **Seed integration branch:** merge `claud` → `dev` (dev is stale; claud is current).
2. Each tool **rebases** its `tool/<name>` branch onto fresh `dev`.
3. Tool builds **only in its owned zone** → PR back into `dev`.
4. **Claude reviews** each PR (tests green · patterns · ownership · contract).
5. `dev` → `main` once the full suite passes.

### Merge order (foundational first)
```
1. CLAUDE  (security/resilience — middleware everyone depends on)
2. OPENCODE (orchestration handlers + autonomy)
3. CODEX   (MCP / detection — needs stable routers)
4. ANTIGRAVITY (observability / dashboard — visualizes everything)
```

### Golden rules
- No two tools edit the same file. Ownership table in §6.
- Shared files (`config.py`, `docker-compose*.yml`, `services/api/app/main.py`,
  `requirements.txt`) are **Claude-merged** — request changes in your PR description.
- Append-only for `config.py`: add a clearly-commented section, never reorder.
- Every tool adds tests for its own modules (separate files) and runs
  `python -m pytest -q` green before opening a PR.

---

## 1. Integration contracts (build against these — they will not change)

| Contract | Signature / rule |
|---|---|
| Agent handler | `async def handler(input_data: dict, ctx: HandlerContext) -> dict` |
| Noise gate (done) | `noise_reduction.evaluate(session, alert, tenant_id) -> NoiseDecision` |
| Few-shot helper | `shared/rag/few_shot.py` → `async def retrieve(agent_type, input_data) -> list[dict]` |
| Tiered routing | `TieredRouter().get_provider(alert, tenant_id, db_session, force_fast=False)` |
| New API router | module exposes `router = APIRouter(prefix=..., tags=[...])`; Claude registers in `main.py` |
| Metrics | add `Gauge`/`Counter` to the existing `CollectorRegistry` in `routers/metrics.py` |
| MCP tool | calls existing router/service functions or read-only queries — never mutate DB directly |

---

## 2. CLAUDE — Security, resilience, integration  (`tool/claude` → merges to `dev`)

**Owns:** `services/api/app/middleware/`, cross-router auth/tenant edits,
`shared/config.py` merges, `docker-compose*.yml`, `services/api/app/main.py`,
`requirements.txt`, the noise-reduction gate (done), and the **integrator role**.

### Tasks
1. Remove hardcoded dashboard credentials → env (`ADMIN_EMAIL`/`ADMIN_PASSWORD`), block login if unset.
2. Enable Jinja2 `autoescape` on the dashboard (kills template XSS).
3. CSRF middleware on dashboard POST/PATCH/DELETE.
4. Admin guard on `POST /settings` (role=admin / `write:settings`).
5. Tenant filters on `/alerts/recent`, `/users`, approval review.
6. Remove nil-UUID tenant fallback in `poller.py`, `soar.py`, `compliance.py` → use `api_key_default_tenant` or reject.
7. Signed session cookie via `itsdangerous` (deps already added).
8. DB pool leak fix — find the leak, restore pool size from 10.
9. Circuit breakers on Ollama / Wazuh API / indexer connectors.
10. Prompt-injection guard: sanitize attacker-controlled log fields before LLM (ZeroLeaks pattern).
11. **Integrator:** seed `dev`, review PRs, resolve conflicts, register routers, merge config/compose, run suite, `dev`→`main`.

---

## 3. CODEX — New isolated services  (`tool/codex` → `dev`)

**Owns:** `services/mcp/` (new), `shared/connectors/` (new connectors),
`services/worker/app/sigma_worker.py` (new). All new files → near-zero conflict.

### Brief (self-contained)
The MCP layer is the highest-leverage gap — `integrations/wazuh_mcp/` is empty.
Build a FastMCP (Python) server exposing the SOC over MCP so Claude Desktop /
Cursor can query it. Mirror the proven tool set from `gbrigandi/mcp-server-wazuh`.

### Tasks
1. **`services/mcp/server.py`** — FastMCP server, tools (read-only unless noted):
   `list_alerts`, `get_triage`, `get_agents`, `list_rules`, `get_stats`,
   `list_vulnerabilities`, `create_case` (write), `run_playbook` (write, gated).
   Back each by existing routers/services or read-only DB queries.
2. **`shared/connectors/jira.py`** — Jira connector as case-ticket sink
   (`jira_url`/`jira_email`/`jira_api_token` already in config).
3. **`services/worker/app/sigma_worker.py`** — compile Sigma rules → Wazuh
   Indexer DSL, run on schedule, raise alerts.
4. Maigret container wiring (`osint_worker` already references `osint_maigret_url`).
5. Wire HIBP key into `credential_leak_worker` (`credential_leak_hibp_api_key`).
- **Request from Claude:** register MCP router/service in compose + main.py;
  add `mcp[server]`, `jira`, `sigma` deps to requirements.
- **Add tests:** `tests/test_mcp_server.py`, `tests/test_jira_connector.py`, `tests/test_sigma_worker.py`.

---

## 4. OPENCODE — Orchestration & agents  (`tool/opencode` → `dev`)

**Owns (exclusive):** `shared/orchestrator/handlers.py`, `shared/orchestrator/engine.py`,
`services/worker/app/agent_worker.py`, `shared/models/agent.py`.

### Brief
Adopt the Wazuh-Openclaw-Autopilot agent model: more roles + autonomy levels +
a policy gate before any write action. Handler signature is fixed (§1).

### Tasks
1. New handlers in `handlers.py`: `correlation` (group related alerts → incident),
   `response_planner` (draft playbook, no execution), `policy_guard` (approve/deny
   by policy before responder acts).
2. Add `autonomy_level` (`read-only`|`approval`|`full`) to `AgentDefinition`.
3. Gate `soar_run` + `case_create` behind `policy_guard` + the existing approvals flow.
4. Evidence-pack generator per case (structured bundle: alert+enrichment+timeline+actions).
5. Register the new handlers in `agent_worker.start()`.
- **Use** `shared/rag/few_shot.py` (Antigravity) for few-shot context in handlers.
- **Request from Claude:** any `config.py` autonomy defaults; schema migration for `agent.py`.
- **Add tests:** extend `tests/test_orchestrator_handlers.py`.

---

## 5. ANTIGRAVITY — Self-learning, observability, dashboard  (`tool/antigravity` → `dev`)

**Owns:** `shared/rag/`, `services/dashboard/`, new self-learning workers,
metric gauges in `routers/metrics.py` (append).

### Brief
Make the system improve itself and make its behavior observable.

### Tasks
1. **`shared/rag/few_shot.py`** — `retrieve(agent_type, input_data)` returns top-K
   similar past tasks from skill memory as few-shot examples (the shared contract).
2. **`services/worker/app/prompt_refiner.py`** — SkillOpt loop: on analyst
   correction, propose a prompt edit, validate, promote `best_skill.md`.
3. **`services/worker/app/meta_agent.py`** — nightly missed-detection scan → RAG.
4. **Kanban HTMX view** for agent runs in the dashboard (live `/agents/runs` poll).
5. **Metrics expansion** in `routers/metrics.py`: `triage_suppressed_total`,
   `triage_kept_total`, per-tier triage counts, queue depth.
6. **MITRE ATT&CK dashboard view** (poller already fills `mitre_tactic`/`technique`).
- **Request from Claude:** wire `few_shot.retrieve()` into `triage_worker.py` (Claude's file).
- **Add tests:** `tests/test_few_shot.py`, `tests/test_prompt_refiner.py`.

---

## 6. File ownership matrix

| Zone | Owner |
|---|---|
| `services/api/app/middleware/` | Claude |
| `services/api/app/routers/*` (auth/tenant edits) | Claude |
| `services/dashboard/` | Antigravity |
| `shared/orchestrator/` | OpenCode |
| `shared/rag/` | Antigravity |
| `services/mcp/` (new) | Codex |
| `shared/connectors/` (new connectors) | Codex |
| `services/worker/app/sigma_worker.py`, osint/credential wiring | Codex |
| `services/worker/app/{prompt_refiner,meta_agent}.py` | Antigravity |
| `services/worker/app/agent_worker.py` | OpenCode |
| `services/worker/app/triage_worker.py` | Claude (done; Antigravity requests 1-line wire) |
| `shared/config.py`, `docker-compose*.yml`, `main.py`, `requirements.txt` | **Claude-merged** |
| `tests/` | per-tool (separate files) |

---

## 7. Definition of done (per PR, enforced at review)

- [ ] `python -m pytest -q` green on the rebased branch
- [ ] Only files in the tool's owned zone changed (shared-file asks listed in PR)
- [ ] New code matches surrounding patterns (logging, async, types)
- [ ] Tests added for new modules
- [ ] STATUS.md section updated
- [ ] Integration contract (§1) honored — no signature drift

---

### Related
[PARALLEL-WORKFLOW.md](PARALLEL-WORKFLOW.md) · [operations/DEPLOYMENT-PLAN.md](operations/DEPLOYMENT-PLAN.md) · [../IMPROVEMENT_PLAN.md](../IMPROVEMENT_PLAN.md)
