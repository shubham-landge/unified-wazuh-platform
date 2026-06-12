# Parallel Workflow for AI Tools

## Branch Strategy

| Branch | Tool | Purpose |
|---|---|---|
| `main` | — | Production-ready, reviewed code only |
| `dev` | — | Integration branch — merge all tool branches here |
| `tool/claude` | Claude | Architecture review, security audit, prompt templates |
| `tool/codex` | Codex | Backend implementation (vulnerability engine, reports, endpoints) |
| `tool/antigravity` | Antigravity | Dashboard enhancements, charting, documentation |
| `tool/opencode` | OpenCode | Runtime fixes, testing, deployment scripts |

## Golden Rule

**No two tools edit the same file simultaneously.** Each tool owns specific files listed below.

---

## Claude — `tool/claude` branch

### Role: Architect & Reviewer (no code writing)

### Create these files:
| File | Purpose |
|---|---|
| `docs/ARCHITECTURE-REVIEW.md` | Review of current architecture against requirements |
| `docs/SECURITY-AUDIT-REPORT.md` | Security audit of all code |
| `docs/API-REVIEW.md` | API endpoint completeness and correctness |

### Review these files and create PR comments:
- All `shared/` code — correctness, safety, import structure
- `services/api/app/routers/*` — auth coverage, rate limiting
- `services/api/app/middleware/*` — security coverage
- Prompt templates in `services/api/app/prompts/` — safety and quality
- `database/schema.sql` — normalization, indexing, multi-tenant
- `docker-compose.yml` — security, health checks, networking

### Do NOT touch:
- Any `.py` implementation files
- `docker-compose.yml`
- `services/` backend code

---

## Codex — `tool/codex` branch

### Role: Backend Builder

### Files to create/modify:

#### High Priority:
| File | Action |
|---|---|
| `shared/connectors/llm_provider.py` | Add cloud provider implementations (OpenAI, Gemini, Claude) |
| `shared/connectors/llm_openai.py` | **New** — OpenAI provider |
| `shared/connectors/llm_gemini.py` | **New** — Gemini provider |
| `shared/connectors/llm_claude.py` | **New** — Claude provider |
| `services/worker/app/vulnerability_worker.py` | **New** — EPSS/KEV enrichment worker |
| `services/api/app/routers/reports.py` | **New** — Report generation endpoints |
| `shared/report_generator.py` | **New** — PDF/Excel report engine |

#### Medium Priority:
| File | Action |
|---|---|
| `services/api/app/routers/triage.py` | Integrate real LLM connector (remove placeholder) |
| `services/worker/app/poller.py` | Add alert deduplication, better field extraction |
| `tests/test_vulnerability_worker.py` | **New** — Tests for vulnerability engine |
| `tests/test_reports.py` | **New** — Tests for report generator |

### Do NOT touch:
- Dashboard templates
- Documentation files
- Database schema (unless adding tables)

---

## Antigravity — `tool/antigravity` branch

### Role: Dashboard & Documentation

### Files to create/modify:

| File | Action |
|---|---|
| `services/dashboard/templates/index.html` | Add alert timeline chart, severity distribution |
| `services/dashboard/templates/alerts.html` | Add severity filter, bulk actions |
| `services/dashboard/templates/cases.html` | Add case creation form, bulk status change |
| `services/dashboard/templates/vulnerabilities.html` | Add risk score distribution chart |
| `services/dashboard/templates/case_detail.html` | Add timeline visualization |
| `services/dashboard/templates/reports.html` | **New** — Report generation interface |
| `services/dashboard/templates/settings.html` | **New** — Platform settings page |
| `services/dashboard/static/charts.js` | **New** — Chart.js integration |
| `docs/DASHBOARD-GUIDE.md` | **New** — Dashboard user guide |
| `docs/DEPLOYMENT-GUIDE.md` | **New** — Deployment walkthrough |

### Do NOT touch:
- API routers
- Worker code
- Connectors

---

## OpenCode — `tool/opencode` branch

### Role: Integrator, Tester, Deployer

### Files to create/modify:

| File | Action |
|---|---|
| `deploy/ec2-setup.sh` | Fix paths, test on EC2 |
| `deploy/healthcheck.sh` | Add dashboard and worker health checks |
| `deploy/monitoring.sh` | **New** — Prometheus/node exporter setup |
| `deploy/nginx.conf` | **New** — TLS termination config |
| `deploy/docker-compose.prod.yml` | **New** — Production docker-compose overrides |
| `tests/test_e2e.py` | **New** — End-to-end integration test |
| `services/api/app/main.py` | Fix any runtime errors discovered during testing |
| `services/worker/app/poller.py` | Fix any runtime errors discovered during testing |

### Run these commands:
```bash
# Verify shared package imports
python3 -c "from shared.config import settings; print('Config OK')"
python3 -c "from shared.models.alert import Alert; print('Models OK')"
python3 -c "from shared.connectors.llm_provider import get_provider; print('Connectors OK')"

# Run unit tests (with mocked DB)
cd /app && PYTHONPATH=/app python3 -m pytest tests/ -v --skip-db
```

---

## Merge Order

```
1. tool/claude  ──> PR into dev  (review completes)
2. tool/codex   ──> PR into dev  (after Claude review)
3. tool/antigravity ──> PR into dev (after codex)
4. tool/opencode ──> PR into dev (final integration)
5. dev ──> main (after all tests pass)
```

## Status Reporting (REQUIRED for all tools)

Every tool MUST update `STATUS.md` before and after each work session.

### Status update commands:
```bash
# When starting work — update your section in STATUS.md
# Change "📝 Not Started" to "🔄 In Progress"

# When completing a phase:
sed -i '' 's/Status:.*📝 Not Started.*$/Status: 🔄 In Progress/' STATUS.md

# When done:
sed -i '' 's/Status:.*🔄 In Progress.*$/Status: ✅ Complete | PR: #X/' STATUS.md
```

### What to report in each update:
1. What you started/finished
2. Files created or modified
3. Any blockers or questions
4. Time spent (rough estimate)

### Opening a PR:
```bash
git checkout -b dev && git merge --no-ff tool/<name>
# Push dev, create PR
gh pr create --base main --head dev --title "Tool: <summary>" --body "See STATUS.md"
```

## Monitoring & Visibility

| Resource | URL/Purpose | Frequency |
|---|---|---|
| **Project Board** | https://github.com/users/shubham-landge/projects/1 | Auto-syncs with PRs |
| **STATUS.md** | `/STATUS.md` in repo root | Update per work session |
| **Branch commits** | `git log --oneline tool/<name> -5` | Any time |
| **Open PRs** | `gh pr list --state open` | Daily review |
| **Status script** | `bash deploy/status.sh` | Quick overview |

## Communication Rules

- Each tool updates `STATUS.md` before starting and after completing work
- If you need to modify a file owned by another tool, create a PR comment on their branch
- Never force-push to main
- Always rebase on latest dev before creating PR
- Update `STATUS.md` in every commit that changes work status
