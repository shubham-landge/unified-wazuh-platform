# Task: Skills, Prompts, and Self-Learning for Tiered Model Strategy

**Branch**: `tool/antigravity` — rebase onto latest `main` (`efd0635`) before starting.
**Owns**: `shared/rag/`, `services/dashboard/`, `prompts/`, `tests/test_prompt_templates.py` (new).

## Context

The system now uses `notmythos:8b` (128K context, cybersecurity-native). To get the best from it:

1. Its prompt templates must be versioned as `.md` files, not hardcoded in code
2. MITRE-mapped skills should be loadable from files, not just DB rows
3. The few-shot RAG should incorporate skill content alongside AgentTask history

## What to build

### 1. Skill format (`prompts/skills/`)

Create a directory `prompts/skills/` with `.skill.md` files using this template:

```markdown
---
skill_id: T1003.001
name: LSASS Credential Dumping Detection
tactic: Credential Access
technique: T1003.001
platforms: [Windows]
data_sources: [Process Monitoring, Sysmon Event 10, Windows Event 4663]
severity: critical
---

# Detection Logic

Monitor for processes accessing lsass.exe with PROCESS_VM_READ or
PROCESS_QUERY_INFORMATION. Common tools: procdump, Task Manager (manual
dump), comsvcs.dll via rundll32.

Sigma rule: `proc_access_lsass.yml`

# Investigation Steps

1. Identify the source process and its parent chain
2. Check for lateral movement indicators (PsExec, WMI, WinRM) in the same time window
3. Collect memory dump and process creation logs (Sysmon Event 1)
4. Verify whether the access was from a known/authorized security tool
```

**Create at least 5 initial skills** covering the most common Wazuh alert types in your environment:

| File | Technique | Alert Type |
|------|-----------|------------|
| `skills/T1003.001.md` | T1003.001 | LSASS access |
| `skills/T1036.005.md` | T1036.005 | Service masquerading |
| `skills/T1078.003.md` | T1078.003 | RDP logon |
| `skills/T1059.001.md` | T1059.001 | PowerShell execution |
| `skills/T1547.004.md` | T1547.004 | Run key persistence |

### 2. Skill loader (`shared/rag/few_shot.py`)

Add a function to `shared/rag/few_shot.py`:

```python
async def load_skill(technique_id: str) -> str:
    """Load a .skill.md file for a MITRE technique. Returns empty string if missing."""
```

- Reads `prompts/skills/{technique_id}.md` from disk
- Extracts and returns the markdown body (everything after `---`)
- Falls back gracefully (empty string) when no file exists
- Caches in memory to avoid repeated disk reads

### 3. Wire skills into few-shot retrieval

Update `retrieve()` in `shared/rag/few_shot.py` to:

- Accept an optional `technique_ids: list[str]` parameter
- When provided, call `load_skill(tid)` for each technique
- Include skill markdown bodies in the returned `list[dict]` as `{"type": "skill", "technique": tid, "content": "..."}`
- Interleave skills with AgentTask experiences in the returned list

### 4. Handler integration

Update handler `_few_shot()` calls in `shared/orchestrator/handlers.py` (triage, response_planner, correlation) to pass the alert's `mitre_technique` so skills are included in few-shot context:

```python
technique_ids = [input_data.get("mitre_technique")] if input_data.get("mitre_technique") else None
few_shot = await _few_shot(agent_type, input_data, technique_ids=technique_ids)
```

### 5. Agent persona files (`agents/`)

Create an `agents/` directory with markdown persona files:

**`agents/triage.md`**:
```markdown
---
agent_type: triage
autonomy_level: read-only
model_tier: full
risk_class: read
tools: [analyze_alert, search_knowledge, lookup_mitre]
---
You are the primary SOC triage agent. Your job is to...
```

**`agents/correlation.md`**, **`agents/response_planner.md`**, **`agents/policy_guard.md`**, **`agents/evidence_pack.md`** — one file for each existing handler.

These files describe what each agent does, its autonomy level, tools, and prompt strategy. They serve as documentation AND could later be loaded by the orchestration engine.

### 6. Tests

Create `tests/test_prompt_templates.py`:

- `test_load_notmythos_prompt_returns_content` — verify `prompts/notmythos_triage.md` exists and is non-empty
- `test_skill_frontmatter_parses` — load a .skill.md, verify `skill_id`, `tactic`, `technique` are accessible
- `test_load_skill_returns_content` — `load_skill("T1003.001")` returns non-empty string
- `test_load_skill_returns_empty_for_missing` — `load_skill("T9999.999")` returns ""
- `test_few_shot_includes_skills` — `retrieve("triage", {}, technique_ids=["T1003.001"])` includes skill content
- `test_prompt_template_has_required_sections` — notmythos_triage.md contains "SYSTEM", "PARAMETER temperature", "mitre_mapping"

## File ownership — only touch

- `prompts/skills/` — new directory with 5 .skill.md files
- `prompts/notmythos_triage.md` — already exists, may add response_planner variant
- `shared/rag/few_shot.py` — add `load_skill()` + update `retrieve()`
- `agents/` — new directory with 5 agent persona .md files
- `tests/test_prompt_templates.py` — new file

## DO NOT touch

- `shared/config.py` — Claude-merged zone
- `shared/connectors/llm_provider.py` — already has `_load_prompt_template()` wired
- `shared/orchestrator/handlers.py` — OpenCode zone
- `docker-compose.yml` / `docker-compose.prod.yml`

## Definition of done

- [ ] `python -m pytest tests/test_prompt_templates.py -q` all green
- [ ] Full suite `python -m pytest -q` green (no regressions)
- [ ] 5 .skill.md files with proper frontmatter
- [ ] 5 agent persona .md files
- [ ] `load_skill("T1003.001")` returns markdown content
- [ ] STATUS.md updated
- [ ] Push to `tool/antigravity`, open PR targeting `dev`
