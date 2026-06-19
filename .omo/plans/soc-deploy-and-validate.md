# soc-deploy-and-validate - Work Plan

## TL;DR (For humans)

**What you'll get:** Your SOC platform running on the Proxmox VM with two new AI models (Foundation-Sec-8B-Instruct for deep analysis, Qwen3-4B for fast triage), connected to Wazuh, able to receive and triage real alerts from your Kali Linux VM, with a fully working dashboard you can check in Safari.

**Why this approach:** Swap models first so the SOC VM boots with the right config. Push to GitHub so the deployment script can pull fresh code. Deploy via the proven quick-start.sh that handles Proxmox, SSH, Docker, and health checks automatically. Then test with real Kali alerts and verify every UI page.

**What it will NOT do:** Change how Wazuh itself works, deploy to AWS/cloud, add GPU support, or build new dashboard features.

**Effort:** Large (8 phases, ~21 file edits, deploy to remote VM, multi-stage testing)
**Risk:** Medium — model pull at deploy time is network-bound (~5GB download); SOC VM may have different Docker state than expected
**Decisions to sanity-check:** New model names for Ollama (must be available on registry), whether to push to GitHub or rsync directly

Your next move: **Approve** this plan so workers execute Phase 1 (model swap edits).

---

> TL;DR (machine): Large, 8-phase plan — model swap (21 file edits) -> git commit/push -> Proxmox deploy -> Wazuh wire check -> Kali testing -> Safari dashboard QA -> perf measurement. 13 todos across 3 waves.

## Scope
### Must have
- Foundation-Sec-8B-Instruct as the full/primary triage model
- Qwen3-4B-Instruct as the fast/noise-gate model
- All config, .env, deploy scripts, dashboards, docs, agents, prompts, and tests updated
- New prompt file for Foundation-Sec
- Git commit + push to origin/main
- Deploy to SOC VM at 192.168.1.100 via Proxmox
- Wazuh agent connectivity check + vulnerability display fix
- End-to-end test: Kali VM generates alerts -> SOC receives + triages
- Dashboard UI check via Playwright/Safari
- Performance metrics captured

### Must NOT have (guardrails, anti-slop, scope boundaries)
- No Ollama provider replacement (stays with OllamaProvider)
- No GPU configuration
- No new dashboard features or UI redesign
- No changes to Wazuh server itself
- No production TLS/cert setup
- No Kubernetes deployment

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- **Test decision:** changes-after (model swap changes verified by running full test suite + eval harness)
- **Evidence:** .omo/evidence/task-*-soc-deploy-and-validate.*
- **Remote verification:** curl health checks on SOC VM, Playwright screenshots of dashboard

## Execution strategy
### Parallel execution waves

**Wave 1 - Model Swap (todos 1-4):**
All model name edits are independent - fan out in parallel.

**Wave 2 - Git + Deploy (todos 5-6):**
Sequential: commit -> push -> deploy script -> wait for health.

**Wave 3 - Validate + Test (todos 7-13):**
Parallel exploration spread: Wazuh check, Kali test, dashboard QA, perf measurement.

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1. Edit config.py | - | 2-4 | - |
| 2. Edit .env + .env.example | - | 5 | 1, 3, 4 |
| 3. Edit deploy/ec2-setup.sh | - | 5 | 1, 2, 4 |
| 4. Edit dashboard/docs/tests | - | 5 | 1, 2, 3 |
| 5. Run tests + commit + push | 1-4 | 6 | - |
| 6. Deploy via Proxmox | 5 | 7-13 | - |
| 7. Check Wazuh services + agents | 6 | 9 | 8 |
| 8. Fix vuln display | 7 | 9 | - |
| 9. Generate Kali alert | 8 | 10-13 | - |
| 10. Verify triage result | 9 | 13 | 11, 12 |
| 11. Dashboard UI check | 9 | 13 | 10, 12 |
| 12. Measure performance | 9 | 13 | 10, 11 |
| 13. Final verification wave | 10, 11, 12 | - | - |

## Todos
> Implementation + Test = ONE todo. Never separate.

- [ ] 1. Edit shared/config.py - swap model defaults
  **What to do:** Change ollama_model (line 44) from "CyberCrew/notmythos-8b" to "Foundation-Sec-8B-Instruct" and ollama_fast_model (line 46) from "qwen2.5:3b-instruct" to "qwen3:4b-instruct". Also update llm_tier_fast_model (line 258) and llm_tier_full_model (line 260) to match.
  **Must NOT do:** Change any other config keys, provider names, or cloud model settings.
  **Parallelization:** Wave 1 | Blocked by: - | Blocks: 5
  **References:** shared/config.py:44-46, shared/config.py:258-260
  **Acceptance criteria:** grep for model names shows Foundation-Sec-8B-Instruct and qwen3:4b-instruct
  **QA scenarios:** Run python -m pytest tests/ -q --tb=short; all pass. Evidence: .omo/evidence/task-1-config-verify.txt
  **Commit:** Y | chore(model): swap notmythos -> Foundation-Sec-8B-Instruct, qwen2.5 -> qwen3:4b-instruct

- [ ] 2. Edit .env, .env.example, and deploy/ec2-setup.sh
  **What to do:** Update OLLAMA_MODEL and OLLAMA_FAST_MODEL in .env (lines 19-20) and .env.example (lines 25-26). Update LLM_TIER_FAST_MODEL and LLM_TIER_FULL_MODEL in .env.example (lines 186,188). In deploy/ec2-setup.sh, change model pull commands (lines 119-126) from notmythos/qwen2.5 to Foundation-Sec/qwen3, and update display text (lines 204-206).
  **Must NOT do:** Change cloud provider API keys or Wazuh connection settings.
  **Parallelization:** Wave 1 | Blocked by: - | Blocks: 5 | Can parallelize with: 1, 3, 4
  **References:** .env:19-20, .env.example:25-26,186,188, deploy/ec2-setup.sh:119-126,204-206
  **Acceptance criteria:** grep for old model names returns no matches in these files
  **QA scenarios:** bash -n deploy/ec2-setup.sh for shell syntax. Evidence: .omo/evidence/task-2-env-verify.txt
  **Commit:** Y (same commit)

- [ ] 3. Update dashboard templates, agent files, and create prompt file
  **What to do:**
  - services/dashboard/app/main.py:776 - change "llama3" to "Foundation-Sec-8B-Instruct"
  - services/dashboard/templates/settings.html:164-167 - update dropdown options
  - services/dashboard/templates/health_grid.html:133,137 - update display names
  - services/dashboard/templates/triage_result_partial.html:67,72,77 - update model detection
  - agents/triage.md:22, agents/response_planner.md:22, agents/correlation.md:20 - update model refs
  - Create prompts/foundation_sec_triage.md (system prompt for Foundation-Sec-8B-Instruct)
  **Must NOT do:** Change HTML structure, CSS classes, or JS behavior.
  **Parallelization:** Wave 1 | Blocked by: - | Blocks: 5 | Can parallelize with: 1, 2, 4
  **References:** services/dashboard/app/main.py:776, settings.html:164-167, health_grid.html:133-137, triage_result_partial.html:67-77, agents/*.md:20-22
  **Acceptance criteria:** grep for old model names returns no matches in these files
  **QA scenarios:** Full test suite passes. Evidence: .omo/evidence/task-3-dashboard-verify.txt
  **Commit:** Y (same commit)

- [ ] 4. Update docs and test files
  **What to do:**
  - docs/operations/DEPLOYMENT-PLAN.md:155-156 - update model strategy table
  - docs/DEPLOYMENT-GUIDE.md - update pull command section
  - README.md:29,64-65 - update model versions and pull commands
  - Update test files: test_connectors.py, test_s0_improvements.py, test_phase3b.py, test_dashboard.py, test_triage_manual_queue.py, test_sanitization.py
  - scripts/eval_triage.py:562 - update default model arg
  **Must NOT do:** Miss any test file; grep thoroughly for old model names.
  **Parallelization:** Wave 1 | Blocked by: - | Blocks: 5 | Can parallelize with: 1, 2, 3
  **References:** docs/operations/DEPLOYMENT-PLAN.md, docs/DEPLOYMENT-GUIDE.md, README.md, tests/test_*.py, scripts/eval_triage.py
  **Acceptance criteria:** grep -r "notmythos\|qwen2.5:3b\|qwen2.5-coder" --include="*.py" --include="*.md" --include="*.sh" --include="*.html" . returns zero matches
  **QA scenarios:** All 679 tests pass. Evidence: .omo/evidence/task-4-test-results.txt
  **Commit:** Y (same commit)

- [ ] 5. Run tests, commit all changes, push to origin
  **What to do:**
  1. Run python -m pytest tests/ -q --tb=short - verify 679 passed
  2. git add -A && git commit -m "feat(model): swap to Foundation-Sec-8B-Instruct + qwen3:4b-instruct"
  3. git push origin main
  **Must NOT do:** Commit without testing first; include secrets in commit.
  **Parallelization:** Wave 2 | Blocked by: 1-4 | Blocks: 6
  **References:** git log
  **Acceptance criteria:** git log --oneline -1 shows commit; git status is clean
  **QA scenarios:** Evidence: .omo/evidence/task-5-git-log.txt
  **Commit:** N (this is the commit step)

- [ ] 6. Deploy to SOC VM via Proxmox
  **What to do:**
  1. Verify Proxmox: curl -sk -X POST "https://192.168.1.200:8006/api2/json/access/ticket" -d "username=root@pam&password=Shubham@1234"
  2. Run bash scripts/quick-start.sh
  3. If quick-start.sh fails (repo mismatch), SSH directly to SOC VM: ssh socadmin@192.168.1.100, cd /opt/unified-wazuh-platform, sudo git pull origin main, sudo docker compose up -d --build
  4. Wait for Ollama to pull Foundation-Sec-8B-Instruct (~5GB) + qwen3:4b-instruct (~2.5GB)
  5. Verify health: curl -sf http://192.168.1.100:8000/health
  6. Verify dashboard: curl -sf http://192.168.1.100
  **Must NOT do:** Run quick-start.sh if Proxmox unreachable (falls back to local tests only).
  **Parallelization:** Wave 2 | Blocked by: 5 | Blocks: 7-13
  **References:** scripts/quick-start.sh, docker-compose.yml
  **Acceptance criteria:** Health returns {"status":"healthy"}; dashboard returns HTML
  **QA scenarios:** Evidence: .omo/evidence/task-6-health.json, .omo/evidence/task-6-docker-ps.txt
  **Commit:** N

- [ ] 7. Check Wazuh services + agents on SOC VM
  **What to do:**
  1. SSH to SOC VM: ssh socadmin@192.168.1.100
  2. docker ps --format 'table {{.Names}}\t{{.Status}}' - all 8 containers must be "Up"
  3. Check Wazuh connectivity via API health
  4. docker compose logs worker --tail 50 | grep triage - verify worker running
  5. Query Wazuh indexer for agent count: curl -sk "https://172.16.6.179:9200/_cat/indices/wazuh-agents*"
  **Must NOT do:** Restart Wazuh services without understanding state.
  **Parallelization:** Wave 3 | Blocked by: 6 | Blocks: 8, 9
  **References:** .env (WAZUH_API_URL, WAZUH_INDEXER_URL)
  **Acceptance criteria:** All 8 containers "Up"; Wazuh connection established
  **QA scenarios:** Evidence: .omo/evidence/task-7-docker-ps.txt, .omo/evidence/task-7-wazuh-health.txt
  **Commit:** N

- [ ] 8. Fix agent vulnerabilities not showing
  **What to do:**
  1. Query Wazuh indexer for vulnerability indices: curl -sk "https://172.16.6.179:9200/_cat/indices/wazuh-states-vulnerabilities-*" 
  2. Check Wazuh agent vuln detection module config
  3. Check SOC vuln worker logs: docker compose logs vulnerability_worker --tail 30
  4. Apply fix in vulnerability_worker.py or vuln_ingester.py if needed
  5. Re-test after fix
  **Must NOT do:** Hardcode index names; use actual cluster state.
  **Parallelization:** Wave 3 | Blocked by: 7 | Blocks: 9
  **References:** services/worker/app/vulnerability_worker.py, services/worker/app/vuln_ingester.py
  **Acceptance criteria:** Vulnerability index returns documents; dashboard shows vulns
  **QA scenarios:** Evidence: .omo/evidence/task-8-vuln-indices.txt, .omo/evidence/task-8-worker-logs.txt
  **Commit:** Y (if code changes needed)

- [ ] 9. Generate test alert from Kali Linux
  **What to do:**
  1. Start Kali VM via Proxmox (find VM ID by listing VMs)
  2. SSH into Kali and generate a test alert (e.g., trigger Wazuh rule, or send test event to Wazuh manager)
  3. Wait 60s+ for poll interval
  4. Check triage result: docker compose logs worker --tail 20 | grep triage
  5. Verify alert appears in SOC API: curl -sf "http://192.168.1.100:8000/alerts?limit=5" -H "X-API-Key: soc-key-001"
  **Must NOT do:** Generate excessive alerts.
  **Parallelization:** Wave 3 | Blocked by: 8 | Blocks: 10-13
  **References:** .env (POLL_INTERVAL_SECONDS: 60), services/worker/app/poller.py
  **Acceptance criteria:** Triage result logged; alert visible in API response
  **QA scenarios:** Evidence: .omo/evidence/task-9-triage-result.txt
  **Commit:** N

- [ ] 10. Verify end-to-end triage pipeline
  **What to do:**
  1. Query API for recent alerts and triage results
  2. Confirm model_name = Foundation-Sec-8B-Instruct or qwen3:4b-instruct
  3. Verify triage verdict stored in database
  **Must NOT do:** Skip checking actual model name.
  **Parallelization:** Wave 3 | Blocked by: 9 | Blocks: 13 | Can parallelize with: 11, 12
  **References:** services/api/app/routers/alerts.py, services/api/app/routers/triage.py
  **Acceptance criteria:** API returns alerts with triage showing new model names
  **QA scenarios:** Evidence: .omo/evidence/task-10-alert-api.json
  **Commit:** N

- [ ] 11. Safari/Playwright dashboard UI check
  **What to do:**
  1. Load http://192.168.1.100 in Playwright/Safari
  2. Screenshot: landing, alerts, cases, agents, vulnerabilities, settings, health
  3. Verify pages render without errors
  4. Check model info shows new models
  **Must NOT do:** Log in with admin creds unless required.
  **Parallelization:** Wave 3 | Blocked by: 9 | Blocks: 13 | Can parallelize with: 10, 12
  **References:** services/dashboard/templates/*.html
  **Acceptance criteria:** All dashboard pages render with data
  **QA scenarios:** Evidence: .omo/evidence/task-11-screenshots/*.png
  **Commit:** N

- [ ] 12. Measure performance
  **What to do:**
  1. Run eval harness: python scripts/eval_triage.py --model Foundation-Sec-8B-Instruct --fast-model qwen3:4b-instruct
  2. Or measure from worker logs: check latency timestamps
  3. Report p50, p95, throughput
  4. Compare to old model benchmarks
  **Must NOT do:** Run destructive tests against production data.
  **Parallelization:** Wave 3 | Blocked by: 9 | Blocks: 13 | Can parallelize with: 10, 11
  **References:** scripts/eval_triage.py, services/worker/app/triage_worker.py
  **Acceptance criteria:** Performance metrics captured and compared
  **QA scenarios:** Evidence: .omo/evidence/task-12-perf.txt
  **Commit:** N

- [ ] 13. Final verification wave
  **What to do:**
  1. Plan compliance: all 12 previous todos done, AC met
  2. Code quality: no old model names, tests pass
  3. Manual QA: alert -> triage -> dashboard display works
  4. Scope fidelity: no scope creep
  **Must NOT do:** Skip any step.
  **Parallelization:** Wave 4 | Blocked by: 10, 11, 12 | Blocks: -
  **Acceptance criteria:** All 4 checkboxes approved
  **QA scenarios:** Evidence: .omo/evidence/task-13-final.txt
  **Commit:** N

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE.
- [ ] F1. Plan compliance audit
- [ ] F2. Code quality review
- [ ] F3. Real manual QA
- [ ] F4. Scope fidelity

## Commit strategy
1. One commit: `feat(model): swap to Foundation-Sec-8B-Instruct + qwen3:4b-instruct`
2. Push to origin/main
3. Optional second commit if vuln fix needs code changes

## Success criteria
- SOC VM dashboard at http://192.168.1.100 loads with data
- Alerts from Kali appear in Wazuh and get triaged by new models
- Dashboard UI renders all pages without errors
- Performance p95 < 45s (eval harness default)
- Wazuh agent vulnerabilities are visible
