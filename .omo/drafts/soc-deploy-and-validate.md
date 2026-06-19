---
slug: soc-deploy-and-validate
status: awaiting-approval
intent: clear
pending-action: write .omo/plans/soc-deploy-and-validate.md
approach: 8-phase plan — model swap (21 file edits) → git commit/push → Proxmox deploy → Wazuh check → Kali test → Safari dashboard QA → perf measurement.
---

# Draft: soc-deploy-and-validate

## Credentials (discovered from scripts/quick-start.sh:13-20)
- **Proxmox:** root@pam / Shubham@1234 at 192.168.1.200:8006
- **SOC VM:** socadmin / Shubham@1234 at 192.168.1.100 (VM ID 200)
- **Wazuh VM:** ID 102
- **Kali VM:** unknown (to discover via Proxmox VM list)

## Key findings
1. Model references across 65+ files — ~21 critical files to edit for model swap
2. Existing deployment script (quick-start.sh) handles Proxmox + SSH + Docker compose
3. SOC VM fast-pulls from GitHub — must git push before deploying
4. 8 Docker services: postgres, redis, ollama, api, worker, dashboard, mcp, maigret
5. Wazuh cluster at 172.16.2.130:55000 (manager) and 172.16.6.179:9200 (indexer)

## Approval gate
status: awaiting-approval
<!-- The plan is written. Present brief to user and wait for explicit okay. -->
