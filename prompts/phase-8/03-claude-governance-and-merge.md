# Task: Governance, Config, and Branch Merge (Integrator Role)

**Branch**: `tool/claude` — rebase onto latest `main` (`efd0635`) before starting.
**Owns**: `shared/config.py`, `docker-compose*.yml`, `services/api/app/main.py`, `.env.example` — AND **integrator role**.

## Phase A: Config and architecture

### 1. Create agent personas as config (`agents/`)

The `agents/` directory (see Antigravity prompt) may have markdown personas. Claude's role is to wire them into the orchestration config if applicable, or at minimum ensure they are documented in `.env.example`. If Antigravity creates the markdown files, Claude ensures the `AgentDefinition.autonomy_level` default in config matches and the `.env.example` references them.

### 2. Create a triggers abstraction (`shared/config.py`)

Add scheduled trigger configuration (Suna-inspired):

```python
# ── Triggers (Suna-inspired cron + webhook automation) ──
# Cron triggers: spawn agent sessions on schedule.
# Format: cron_expression;agent_type;description
# Example: "0 2 * * *;meta_agent;Nightly missed-detection scan"
triggers_cron: str = ""
# Webhook triggers: spawn agents when an external event fires.
# Format: path_secret;agent_type;description
# Example: "siem-webhook-a1b2c3;triage;External SIEM webhook"
triggers_webhooks: str = ""
# Auto-approve triggers from agents at or above this autonomy level.
triggers_auto_approve_autonomy: str = "full"
```

### 3. Update `.env.example`

Already done in main — verify no conflicts and add triggers section:

```env
# ─── Triggers (Suna-inspired automation) ───
# Cron triggers: cron_expression;agent_type;description
# Example: "0 2 * * *;meta_agent;Nightly missed-detection scan"
TRIGGERS_CRON=
# Webhook triggers: path_secret;agent_type;description
TRIGGERS_WEBHOOKS=
TRIGGERS_AUTO_APPROVE_AUTONOMY=full
```

## Phase B: Branch integration (Claude's integrator role)

Merge order (foundational first):

```
1. CODEX        (tool/codex)        → dev   [MCP expansion]
2. ANTIGRAVITY  (tool/antigravity)  → dev   [skills + prompts]
3. CLAUDE       (tool/claude)       → dev   [governance, then dev→main]
```

### Per-PR review checklist

For each incoming PR:

- [ ] `python -m pytest -q` green on the branch
- [ ] Only files in the tool's zone changed (if shared files touched, request explanation)
- [ ] Integration contracts honored (MCP tool signature, few_shot.retrieve signature, handler input_data format)
- [ ] No changes to other tools' exclusive zones
- [ ] STATUS.md section updated by the tool
- [ ] New tests for new modules
- [ ] Code matches surrounding patterns (async, types, logging)

### Merge actions (Claude-only)

After Codex and Antigravity branches are merged into `dev`:

1. Run full test suite: `python -m pytest -q`
2. Check for new router imports in `services/api/app/main.py` — register them if Antigravity/Codex added new routers
3. Check `docker-compose*.yml` for new service blocks — no new containers should be needed for this phase
4. Merge `dev` → `main`
5. Tag: `git tag v0.4.0 -m "Phase 8: Tiered model strategy + skills + MCP expansion"`
6. Push `main` and tag

### Conflict resolution rules

- `shared/config.py`: Claude-only. If another tool needs a config field, they request it in PR description; Claude adds it.
- `llm_provider.py`: Antigravity may add prompt loading; Claude may update model parameters. Resolve by keeping both changes — prompt loading + model params.
- `services/mcp/server.py`: Codex owns. Antigravity doesn't touch.
- `tests/`: Each tool uses separate test files. No conflicts.
- `STATUS.md`: Append-only. Resolve by concatenating sections.

## Phase C: Performance checklist

Before tagging:

- [ ] `notmythos:8b` pulled on soc-ollama? (run `docker compose exec ollama ollama list | grep notmythos`)
- [ ] Triage latency under 300s on the Dell? (check worker logs for `tokens_input` / `tokens_output`)
- [ ] Dashboard loads at `http://192.168.1.101:80`
- [ ] MCP server at `http://192.168.1.101:9000/tools` returns 14 tools
- [ ] Health check `/health/full` returns all services connected

## Definition of done

- [ ] All three branches merged into `dev`
- [ ] `dev` → `main` with tag `v0.4.0`
- [ ] Full test suite green on `main`
- [ ] `shared/config.py` has triggers fields (append-only)
- [ ] `.env.example` has triggers section
- [ ] No regression: 309+ tests passing
