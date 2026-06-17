# ATT&CK Skill DB Import Plan

> **Status**: Design / implementation plan. Not yet executed.  
> **Updated**: 2026-06-17  
> **Scope**: How to import the ~754 ATT&CK-mapped skills from `mukul975/awesome-attck-skill-db` into the platform RAG store (`knowledge_chunks`) so triage, response planning, and few-shot retrieval improve.

---

## 1. Why import ATT&CK skills

Current behavior:
- Triage uses a generic system prompt.
- `shared/rag/few_shot.py` only retrieves past `AgentTask` experiences.
- The platform has no built-in knowledge of which defensive actions map to which MITRE techniques.

After import:
- LLM prompts include technique-specific detection logic, investigation steps, and response actions.
- Response planner can reference known defensive playbooks per technique.
- Few-shot retrieval can combine historical cases with canonical skill definitions.

---

## 2. Source data

### Primary source
`mukul975/awesome-attck-skill-db` — a curated collection of cybersecurity skills mapped to MITRE ATT&CK tactics and techniques.

### Expected schema (based on common skill-db formats)
Each skill is typically a JSON or YAML record with fields such as:

```json
{
  "id": "SKILL-0001",
  "name": "Detect LSASS Memory Access",
  "description": "Identify processes attempting to read LSASS memory, often credential dumping.",
  "tactic": "Credential Access",
  "technique_id": "T1003.001",
  "technique_name": "OS Credential Dumping: LSASS Memory",
  "platforms": ["Windows"],
  "data_sources": ["Process Monitoring", "Command Monitoring"],
  "detection_logic": "Monitor for processes like Task Manager, procdump, or custom tools accessing lsass.exe.",
  "investigation_steps": ["Identify the process", "Check parent/child relationships", "Collect memory dump"],
  "mitigation": "Enable Credential Guard, restrict debug privileges.",
  "confidence": "high",
  "references": ["https://attack.mitre.org/techniques/T1003/001/"]
}
```

If the upstream schema differs, the importer normalizes it to this canonical shape.

---

## 3. Import pipeline

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Clone / fetch  │     │  Normalize to   │     │  Chunk + embed  │
│  awesome-attck  │────▶│  canonical JSON │────▶│  via Ollama     │
│  -skill-db      │     │  per skill      │     │  nomic-embed    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Deduplicate by │     │  Tag with       │     │  Write to       │
│  technique_id   │     │  source + ATT&CK│     │  knowledge_     │
│                 │     │  metadata       │     │  chunks         │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### 3.1 Step-by-step

1. **Fetch**
   - `git clone https://github.com/mukul975/awesome-attck-skill-db.git` during build or seed step.
   - Or fetch raw JSON via GitHub API to avoid a git dependency.

2. **Normalize**
   - Recursively parse `.json`, `.yaml`, `.yml` files.
   - Map each record to the canonical schema above.
   - Skip records without a `technique_id`.

3. **Deduplicate**
   - Key by `technique_id + name`.
   - Prefer the record with the most complete fields.

4. **Chunk**
   - Each skill becomes one chunk if under `rag_chunk_size` (default 1000 tokens/words).
   - Long skills are split with overlap using `shared/rag/vector_store.chunk_and_ingest`.

5. **Embed and store**
   - Call `shared.rag.embeddings.embed_text()` per chunk.
   - Insert into `knowledge_chunks` with:
     - `source`: `attck_skill_db:<technique_id>:<skill_id>`
     - `metadata`: tactic, technique_id, platforms, data_sources, references

---

## 4. Proposed implementation

### 4.1 New script: `scripts/seed_attack_skills.py`

A one-off idempotent seed script:

```python
async def seed_attack_skills(db_url: str, repo_url: str, local_path: str):
    # 1. Clone or update repo
    # 2. Normalize records
    # 3. For each skill, call ingest_knowledge(...)
    # 4. Report counts
```

Run manually or on container startup ( guarded by `ATTACK_SEED_ON_STARTUP=true`).

### 4.2 New worker enhancement: `services/worker/app/rag_worker.py`

If the RAG worker already ingests documents, extend it with an `ATT&CK` source type so skills refresh on schedule.

### 4.3 Configuration (add to `shared/config.py`)

```python
attack_skill_db_enabled: bool = True
attack_skill_db_repo_url: str = "https://github.com/mukul975/awesome-attck-skill-db"
attack_skill_db_local_path: str = "/app/data/awesome-attck-skill-db"
attack_skill_db_refresh_interval_hours: int = 168  # weekly
```

### 4.4 Integration with triage and response planner

In `shared/orchestrator/handlers.py::response_planner()` and `services/worker/app/triage_worker.py`:

```python
from shared.rag.vector_store import search_knowledge
skills = await search_knowledge(
    f"{alert.mitre_tactic} {alert.mitre_technique} response investigation",
    session,
    top_k=3,
)
```

Append matching skill text to the system prompt under a `# Relevant ATT&CK skills` section.

---

## 5. Expected chunk count and storage

| Assumption | Value |
|------------|-------|
| Skills | ~754 |
| Avg words per skill | ~250 |
| Chunk size | 1000 words |
| Total chunks | ~754 (most fit in one chunk) |
| Embedding dims (nomic-embed-text) | 768 |
| Storage per chunk (JSON embedding) | ~6 KB |
| Total storage | ~4.5 MB |

Negligible for PostgreSQL. No vector extension required; current in-memory cosine similarity in `search_knowledge()` works fine at this scale.

---

## 6. Validation checklist

After seeding:

- [ ] `SELECT COUNT(*) FROM knowledge_chunks WHERE source LIKE 'attck_skill_db:%'` returns ~754.
- [ ] A triage query for `T1003.001` returns the LSASS skill.
- [ ] Response planner for a `T1003.001` alert includes investigation steps from the skill.
- [ ] No duplicate technique IDs with identical names.
- [ ] Embedding generation succeeds for all chunks (check logs for `Embedding API returned` warnings).

---

## 7. Future expansions

| Source | What it adds | When |
|--------|--------------|------|
| Sigma rules | Detection-as-code mappings | With `sigma_worker` |
| Sentinel analytics | Cloud-native detections | Sentinel → Sigma pipeline |
| Internal runbooks | Organization-specific procedures | Manual upload via KB dashboard |
| MITRE ATT&CK dataset | Official technique descriptions | Always up-to-date fallback |

---

## 8. Related documents

- [VISION-AUTONOMOUS-SOC.md](VISION-AUTONOMOUS-SOC.md) — why ATT&CK skill import is Wave 3
- [SKILL-OPT.md](SKILL-OPT.md) — how imported skills combine with learned skill memory
- [UNIFIED-ARCHITECTURE.md](UNIFIED-ARCHITECTURE.md) — RAG/embedding architecture
- [AI-MODEL-REVIEW.md](AI-MODEL-REVIEW.md) — local embedding model (`nomic-embed-text`)
